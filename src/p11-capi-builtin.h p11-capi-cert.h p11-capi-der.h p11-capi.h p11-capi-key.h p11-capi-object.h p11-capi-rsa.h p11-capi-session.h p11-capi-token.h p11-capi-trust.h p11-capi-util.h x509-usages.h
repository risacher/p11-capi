p11-capi-cert.c:	if(!CryptDecodeObject(P11c_ENCODINGS, X509_BASIC_CONSTRAINTS, 
p11-capi-cert.c:	if(CryptDecodeObject(P11c_ENCODINGS, X509_BASIC_CONSTRAINTS, 
p11-capi-cert.c:	if(!CryptHashCertificate(0, CALG_SHA1, 0, cert->pbCertEncoded, 
p11-capi-cert.c:	if(!CryptHashCertificate(0, CALG_SHA1, 0, cert->pbCertEncoded, 
p11-capi-cert.c:		if(!CryptEncodeObject(X509_ASN_ENCODING, X509_MULTI_BYTE_INTEGER,
p11-capi-cert.c:			if(!CryptDecodeObject(P11c_ENCODINGS, X509_MULTI_BYTE_INTEGER,
p11-capi-cert.c:			if(!CryptDecodeObject(P11c_ENCODINGS, X509_MULTI_BYTE_INTEGER,
p11-capi-key.c:	if(!CryptAcquireContextW(&prov, kdata->prov_info->pwszContainerName, 
p11-capi-key.c:          if(!CryptAcquireContextW(&prov, kdata->prov_info->pwszContainerName, 
p11-capi-key.c:	if(!CryptGetUserKey(prov, kdata->prov_info->dwKeySpec, &key))
p11-capi-key.c:		CryptReleaseContext(prov, 0);
p11-capi-key.c:	if(CryptExportKey(key, 0, PUBLICKEYBLOB, 0, NULL, &kdata->raw_public_key.cbData))
p11-capi-key.c:			if(CryptExportKey(key, 0, PUBLICKEYBLOB, 0, kdata->raw_public_key.pbData, 
p11-capi-key.c:	CryptReleaseContext(prov, 0);
p11-capi-key.c:	CryptDestroyKey(key);
p11-capi-key.c:	if(!CryptEnumKeyIdentifierProperties((CRYPT_HASH_BLOB*)&kobj->key_identifier, 
p11-capi-key.c:	if(!CryptEnumKeyIdentifierProperties(find_id.cbData != 0 ? &find_id : NULL, 
p11-capi-rsa.c:  if(CryptAcquireContextW(&prov, prov_info->pwszContainerName, prov_info->pwszProvName,
p11-capi-rsa.c:      if(CryptCreateHash(prov, algorithm, 0, 0, &hash))
p11-capi-rsa.c:          if(CryptGetHashParam(hash, HP_HASHSIZE, (BYTE*)&check, &len, 0))
p11-capi-rsa.c:              if(CryptSetHashParam(hash, HP_HASHVAL, hash_data, 0))
p11-capi-rsa.c:                  if(CryptSignHash(hash, prov_info->dwKeySpec, 
p11-capi-rsa.c:    CryptDestroyHash(hash);
p11-capi-rsa.c:    CryptReleaseContext(prov, 0);
p11-capi-rsa.c:  if(CryptAcquireContextW(&prov, prov_info->pwszContainerName, prov_info->pwszProvName,
p11-capi-rsa.c:      if(CryptGetUserKey(prov, prov_info->dwKeySpec, &key))
p11-capi-rsa.c:          if(CryptDecrypt(key, 0, TRUE, 0, buffer, n_result))
p11-capi-rsa.c:    CryptDestroyKey(key);
p11-capi-rsa.c:    CryptReleaseContext(prov, 0);
p11-capi-session.c:typedef struct _CryptoContext 
p11-capi-session.c:CryptoContext;
p11-capi-session.c:	CryptoContext* ctx;
p11-capi-session.c:		ctx = (CryptoContext*)sess->operation_data;
p11-capi-session.c:	CryptoContext* ctx;
p11-capi-session.c:	ctx = calloc(1, sizeof(CryptoContext));
p11-capi-session.c:	CryptoContext *ctx;
p11-capi-session.c:	ctx = (CryptoContext*)sess->operation_data;
p11-capi-session.c:	CryptoContext* ctx;
p11-capi-session.c:	ctx = calloc(1, sizeof(CryptoContext));
p11-capi-session.c:	CryptoContext *ctx;
p11-capi-session.c:	ctx = (CryptoContext*)sess->operation_data;
p11-capi-trust.c:		if(!CryptHashCertificate(0, attr->type == CKA_CERT_MD5_HASH ? CALG_MD5 : CALG_SHA1,
p11-capi-trust.c:	if(!CryptDecodeObject(P11c_ENCODINGS, X509_KEY_USAGE, 
p11-capi-trust.c:	if(CryptDecodeObject(P11c_ENCODINGS, X509_KEY_USAGE, 
