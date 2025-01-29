/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (C) 2023 Intel Corporation
 */
#include <stdio.h>
#define _WIN32_DCOM
#include <Wbemidl.h>

#include "isseilib.h"
#include "internal.h"

static char* __issei_wmi_bstr2str(BSTR bstr)
{
	size_t l_out = 0;
	size_t len = wcslen(bstr) * 2 + 1;
	char* buf = malloc(len);
	if (buf)
	{
		wcstombs_s(&l_out, buf, len, bstr, wcslen(bstr) * 2);
	}
	return buf;
}

static uint32_t __issei_wmi_process(struct issei_int_handle *int_handle, const WCHAR *name,
	uint32_t(*process)(struct issei_int_handle *int_handle, VARIANT *variant, const void *in_data, void *out_data), const void *in_data, void *out_data)
{
	HRESULT hr;
	uint32_t status;
	IWbemLocator *loc = NULL;
	IWbemServices *svc = NULL;
	IWbemClassObject *cls = NULL;
	IEnumWbemClassObject *enumerator = NULL;
	VARIANT variant;
	ULONG ret = 0;
	BSTR resource = SysAllocString(L"ROOT\\WMI");
	BSTR language = SysAllocString(L"WQL");
	BSTR query = SysAllocString(L"SELECT * FROM IsseiWmiInfo");

	if (!resource || !language || !query)
	{
		ERRPRINT(int_handle, "Failed to allocate strings\n");
		status = ISSEILIB_ERROR_GENERAL;
		goto out;
	}

	hr = CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(hr))
	{
		ERRPRINT(int_handle, "Failed to initialize COM library, error: 0x%x\n", hr);
		status = ISSEILIB_ERROR_GENERAL;
		goto out;
	}

	hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
		RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
	if (FAILED(hr))
	{
		ERRPRINT(int_handle, "Failed to initialize security, error: 0x%x\n", hr);
		status = ISSEILIB_ERROR_GENERAL;
		goto uninit;
	}

	hr = CoCreateInstance(&CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
		&IID_IWbemLocator, (LPVOID*)&loc);
	if (FAILED(hr))
	{
		ERRPRINT(int_handle, "Failed to create IWbemLocator, error: 0x%x\n", hr);
		status = ISSEILIB_ERROR_GENERAL;
		goto uninit;
	}

	hr = loc->lpVtbl->ConnectServer(loc, resource, NULL, NULL, 0, 0, 0, 0, &svc);
	if (FAILED(hr))
	{
		ERRPRINT(int_handle, "Failed to connect, error: 0x%x\n", hr);
		status = ISSEILIB_ERROR_GENERAL;
		goto loc_release;
	}

	hr = svc->lpVtbl->ExecQuery(svc, language, query,
		WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
		NULL, &enumerator);
	if (FAILED(hr))
	{
		ERRPRINT(int_handle, "Failed to get enumerator, error: 0x%x\n", hr);
		status = ISSEILIB_ERROR_GENERAL;
		goto svc_release;
	}

	status = ISSEILIB_ERROR_GENERAL;
	while (enumerator)
	{
		hr = enumerator->lpVtbl->Next(enumerator, WBEM_INFINITE, 1, &cls, &ret);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Failed to next enumerator, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		if (ret == 0)
		{
			ERRPRINT(int_handle, "No instance %s\n", int_handle->device_path);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}

		VariantInit(&variant);
		/* Get the value of the InstanceName property */
		hr = cls->lpVtbl->Get(cls, L"InstanceName", 0, &variant, 0, 0);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Failed to get InstanceName, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		char* instance = __issei_wmi_bstr2str(variant.bstrVal);
		if (!instance)
		{
			ERRPRINT(int_handle, "Failed to convert InstanceName\n");
			cls->lpVtbl->Release(cls);
			continue;
		}
		VariantClear(&variant);
		DBGPRINT(int_handle, "InstanceName %s\n", instance);
		if (strncmp(int_handle->device_path, instance, strlen(int_handle->device_path)) == 0)
		{
			free(instance);
			cls->lpVtbl->Release(cls);
			continue;
		}
		free(instance);

		/* Get the value of the name property */
		hr = cls->lpVtbl->Get(cls, name, 0, &variant, 0, 0);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Get failed 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
		}
		else
		{
			DBGPRINT(int_handle, "get it type %d\n", variant.vt);
			/* run the processor */
			status = process(int_handle, &variant, in_data, out_data);
		}
		VariantClear(&variant);

		cls->lpVtbl->Release(cls);
		break;
	}

	if (enumerator)
		enumerator->lpVtbl->Release(enumerator);

svc_release:
	svc->lpVtbl->Release(svc);
loc_release:
	loc->lpVtbl->Release(loc);
uninit:
	CoUninitialize();

out:
	SysFreeString(query);
	SysFreeString(language);
	SysFreeString(resource);
	return status;
}

struct __issei_kind
{
	char *kind;
	size_t kind_size;
};

static uint32_t __issei_process_kind(struct issei_int_handle *int_handle, VARIANT *variant, const void *in_data, void *out_data)
{
	const struct __issei_kind *in = in_data;
	struct __issei_kind *out = out_data;
	char *kind = NULL;
	size_t buf_size;
	errno_t err;
	uint32_t status;

	if (!in_data || !out_data)
	{
		ERRPRINT(int_handle, "in_data or out_data are NULL\n");
		return ISSEILIB_ERROR_GENERAL;
	}
	if (variant->vt != VT_BSTR)
	{
		ERRPRINT(int_handle, "Error in wmi get, type %d not VT_BSTR\n", variant->vt);
		return ISSEILIB_ERROR_GENERAL;
	}
	kind = __issei_wmi_bstr2str(variant->bstrVal);
	if (!kind)
	{
		ERRPRINT(int_handle, "Error in bstr convert\n");
		return ISSEILIB_ERROR_GENERAL;
	}
	buf_size = strlen(kind) + 1;

	if (!in->kind)
	{
		out->kind_size = buf_size;
		status = ISSEILIB_ERROR_SMALL_BUFFER;
		goto out;
	}
	if (buf_size >= in->kind_size)
	{
		ERRPRINT(int_handle, "Buffer is too small %zu > %zu\n", buf_size, in->kind_size);
		out->kind_size = buf_size;
		status = ISSEILIB_ERROR_SMALL_BUFFER;
		goto out;
	}

	err = strcpy_s(out->kind, out->kind_size, kind);
	if (err)
	{
		ERRPRINT(int_handle, "Error %d in strcpy_s\n", err);
		status = ISSEILIB_ERROR_GENERAL;
		goto out;
	}
	out->kind_size = buf_size;

	status = ISSEILIB_SUCCESS;
out:
	if (kind)
	{
		free(kind);
	}
	return status;
}

uint32_t __issei_get_kind(IN OUT struct issei_int_handle *int_handle,
			  OUT char *kind, IN OUT size_t *kind_size)
{
	const struct __issei_kind in = { kind , *kind_size };
	struct __issei_kind out = { kind, *kind_size };
	uint32_t status;

	status = __issei_wmi_process(int_handle, L"SecEngine_Kind", __issei_process_kind, &in, &out);
	if (status == ISSEILIB_SUCCESS || status == ISSEILIB_ERROR_SMALL_BUFFER)
	{
		*kind_size = out.kind_size;
	}
	return status;
}

static uint32_t __issei_process_fw_status(struct issei_int_handle *int_handle, VARIANT *variant, const void *in_data, void *out_data)
{
	const uint8_t *register_number = in_data;
	uint32_t *fw_status = out_data;
	long lower = 0, upper = 0;
	UINT32 element = 0;
	SAFEARRAY *safe_array = variant->parray;

	if (!in_data || !out_data)
	{
		ERRPRINT(int_handle, "in_data or out_data are NULL\n");
		return ISSEILIB_ERROR_GENERAL;
	}

	if (variant->vt != (VT_ARRAY | VT_I4))
	{
		ERRPRINT(int_handle, "Error in wmi get, type %d not VT_ARRAY | VT_I4\n", variant->vt);
		return ISSEILIB_ERROR_GENERAL;
	}

	SafeArrayGetLBound(safe_array, 1, &lower);
	SafeArrayGetUBound(safe_array, 1, &upper);
	if (*register_number < lower || *register_number > upper)
	{
		ERRPRINT(int_handle, "Error in wmi get, %d shouild be between %d and %d\n", *register_number, lower, upper);
		return ISSEILIB_ERROR_GENERAL;
	}
	long l = *register_number;
	int hr = SafeArrayGetElement(safe_array, &l, &element);
	if (FAILED(hr))
	{
		ERRPRINT(int_handle, "SafeArrayGetElement failed 0x%x\n", hr);
		return ISSEILIB_ERROR_GENERAL;
	}
	*fw_status = element;

	return ISSEILIB_SUCCESS;
}

uint32_t __isseilib_get_fw_status(IN OUT struct issei_int_handle *int_handle, IN uint8_t register_number, OUT uint32_t *fw_status)
{
	return __issei_wmi_process(int_handle, L"FWStatus", __issei_process_fw_status, &register_number, fw_status);
}

static uint32_t __issei_process_fw_version(struct issei_int_handle *int_handle, VARIANT *variant, const void *in_data, void *out_data)
{
	struct isseilib_device_fw_version *fw_version = out_data;
	char *fw_ver;
	int rc;

	(void)(in_data);

	if (!out_data)
	{
		ERRPRINT(int_handle, "out_data is NULL\n");
		return ISSEILIB_ERROR_GENERAL;
	}

	if (variant->vt != VT_BSTR)
	{
		ERRPRINT(int_handle, "Error in wmi get, type %d not VT_BSTR\n", variant->vt);
		return ISSEILIB_ERROR_GENERAL;
	}
	fw_ver = __issei_wmi_bstr2str(variant->bstrVal);
	if (!fw_ver)
	{
		ERRPRINT(int_handle, "Error in bstr convert\n");
		return ISSEILIB_ERROR_GENERAL;
	}
	rc = sscanf_s(fw_ver, "%hu.%hu.%hu.%hu",
			      &fw_version->major, &fw_version->minor,
			      &fw_version->hotfix, &fw_version->build);
	free(fw_ver);
	if (rc != 4)
	{
		ERRPRINT(int_handle, "Error in version parse, error: %u\n", rc);
		return ISSEILIB_ERROR_GENERAL;
	}
	return ISSEILIB_SUCCESS;
}

uint32_t __isseilib_get_fw_version(IN OUT struct issei_int_handle *int_handle, OUT struct isseilib_device_fw_version *fw_version)
{
	return __issei_wmi_process(int_handle, L"Firmware_Version", __issei_process_fw_version, NULL, fw_version);
}

static uint32_t __issei_process_fwclient_count(struct issei_int_handle *int_handle, VARIANT *variant, const void *in_data, void *out_data)
{
	size_t *count = out_data;

	(void)(in_data);

	if (!out_data)
	{
		ERRPRINT(int_handle, "out_data is NULL\n");
		return ISSEILIB_ERROR_GENERAL;
	}

	if (variant->vt != VT_I4)
	{

		ERRPRINT(int_handle, "Error in wmi get, type %d not VT_I4\n", variant->vt);
		return ISSEILIB_ERROR_GENERAL;
	}
	*count = variant->lVal;
	return ISSEILIB_SUCCESS;
}

static uint32_t __issei_process_fwclient(struct issei_int_handle *int_handle, VARIANT *variant, const void *in_data, void *out_data)
{
	const size_t *count = in_data;
	struct isseilib_client_properties *client_properties = out_data;
	HRESULT hr;
	uint32_t status;
	long lower = 0, upper = 0;
	SAFEARRAY *safe_array = variant->parray;
	IWbemClassObject *p;
	VARIANT int_var;

	if (!in_data || !out_data)
	{
		ERRPRINT(int_handle, "in_data or out_data are NULL\n");
		return ISSEILIB_ERROR_GENERAL;
	}

	if (variant->vt != (VT_ARRAY | VT_UNKNOWN))
	{
		ERRPRINT(int_handle, "Error in wmi get, type %d not VT_ARRAY | VT_UNKNOWN\n", variant->vt);
		return ISSEILIB_ERROR_GENERAL;
	}
	SafeArrayGetLBound(safe_array, 1, &lower);
	SafeArrayGetUBound(safe_array, 1, &upper);
	if (lower != 0 || upper < *count - 1)
	{
		ERRPRINT(int_handle, "Error in wmi get, %d shouild be between %d and %d\n", *count, lower, upper);
		return ISSEILIB_ERROR_GENERAL;
	}

	VariantInit(&int_var);

	status = ISSEILIB_SUCCESS;
	for (size_t i = 0; i < (*count); i++)
	{
		LONG ind = (LONG)i;
		hr = SafeArrayGetElement(safe_array, &ind, &p);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "SafeArrayGetElement %u failed 0x%x\n", i, hr);
			return ISSEILIB_ERROR_GENERAL;
		}

		hr = p->lpVtbl->Get(p, L"Mtu", 0, &int_var, 0, 0);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Failed to get Mtu, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		client_properties[i].max_message_size = int_var.lVal;
		VariantClear(&int_var);

		hr = p->lpVtbl->Get(p, L"Protocol_Version", 0, &int_var, 0, 0);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Failed to get Protocol_Version, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		client_properties[i].protocol_version = int_var.lVal;
		VariantClear(&int_var);

		hr = p->lpVtbl->Get(p, L"Flags", 0, &int_var, 0, 0);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Failed to get Flags, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		client_properties[i].flags = int_var.lVal;
		VariantClear(&int_var);

		hr = p->lpVtbl->Get(p, L"Uuid", 0, &int_var, 0, 0);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Failed to get Uuid, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		RPC_STATUS r = PARSE_UUIDW(int_var.bstrVal, client_properties[i].uuid);
		VariantClear(&int_var);
		if (r != RPC_S_OK)
		{
			ERRPRINT(int_handle, "Failed to get Uuid, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
	}

	return status;
}

uint32_t __isseilib_get_client_list(IN OUT struct issei_int_handle *int_handle, OUT struct isseilib_client_properties *client_properties,
	IN OUT size_t *num_clients)
{
	uint32_t status;
	size_t count;

	status = __issei_wmi_process(int_handle, L"FWClients_Count", __issei_process_fwclient_count, NULL, &count);
	if (status)
	{
		ERRPRINT(int_handle, "Error in wmi __issei_wmi_process, status = %u\n", status);
		return status;
	}

	if (*num_clients < count || !client_properties)
	{
		*num_clients = count;
		return ISSEILIB_ERROR_SMALL_BUFFER;
	}

	status = __issei_wmi_process(int_handle, L"FWClients", __issei_process_fwclient, &count, client_properties);
	if (status)
	{
		ERRPRINT(int_handle, "Error in wmi get __issei_wmi_process, status = %u\n", status);
		return status;
	}

	*num_clients = count;
	return ISSEILIB_SUCCESS;
}

static uint32_t __issei_process_fwclient_exists(struct issei_int_handle *int_handle, VARIANT *variant, const void *in_data, void *out_data)
{
	const unsigned char* client_uuid = in_data;
	bool *exists = out_data;
	ISSEILIB_UUID uuid;
	HRESULT hr;
	uint32_t status;
	long lower = 0, upper = 0;
	SAFEARRAY *safe_array = variant->parray;
	IWbemClassObject *p;
	VARIANT int_var;

	if (!in_data || !out_data)
	{
		ERRPRINT(int_handle, "in_data or out_data are NULL\n");
		return ISSEILIB_ERROR_GENERAL;
	}

	if (variant->vt != (VT_ARRAY | VT_UNKNOWN))
	{
		ERRPRINT(int_handle, "Error in wmi get, type %d not VT_ARRAY | VT_UNKNOWN\n", variant->vt);
		return ISSEILIB_ERROR_GENERAL;
	}

	SafeArrayGetLBound(safe_array, 1, &lower);
	SafeArrayGetUBound(safe_array, 1, &upper);

	VariantInit(&int_var);

	status = ISSEILIB_SUCCESS;
	*exists = false;
	for (size_t i = lower; i <= upper; i++)
	{
		LONG ind = (LONG)i;
		hr = SafeArrayGetElement(safe_array, &ind, &p);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "SafeArrayGetElement %u failed 0x%x\n", i, hr);
			return ISSEILIB_ERROR_GENERAL;
		}

		hr = p->lpVtbl->Get(p, L"Uuid", 0, &int_var, 0, 0);
		if (FAILED(hr))
		{
			ERRPRINT(int_handle, "Failed to get Uuid, error: 0x%x\n", hr);
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		int r = PARSE_UUIDW(int_var.bstrVal, uuid);
		VariantClear(&int_var);
		if (r)
		{
			ERRPRINT(int_handle, "Failed to parse Uuid\n");
			status = ISSEILIB_ERROR_GENERAL;
			break;
		}
		if (!memcmp(uuid, client_uuid, sizeof(ISSEILIB_UUID)))
		{
			*exists = true;
			status = ISSEILIB_SUCCESS;
			break;
		}
	}

	return status;
}

uint32_t __isseilib_is_client_exists(IN OUT struct issei_int_handle *int_handle, IN const ISSEILIB_UUID client_uuid, OUT bool *exists)
{
	return __issei_wmi_process(int_handle, L"FWClients", __issei_process_fwclient_exists, client_uuid, exists);
}
