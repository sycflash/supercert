#!/usr/bin/python
#coding: utf-8
#
# author: suyanchun
# 2017-2-12

# 用途1: ./supercert.py 证书文件，验证证书合法性，验证证书链是否完整
# 用途2: ./supercert.py 站点url，验证站点证书合法性，以及检测站点支持的ssl版本
# 依赖pyopenssl

#from httplib2 import request
import datetime
from OpenSSL.crypto import load_certificate,dump_certificate,FILETYPE_PEM,FILETYPE_ASN1
import re

import sys,os

# url正则表达式
urlreg = re.compile(
	r'^((?:http|ftp)s?://)' # http:// or https://
	r'((?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
	r'localhost|' #localhost...
	r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))' # ...or ip
	r'((?::\d+))?' # optional port
	r'(?:/?|[/?]\S+)?$', re.IGNORECASE)

# 加载证书
def load_local_cert(cert_path):
	if not os.path.isfile(cert_path):
		return 1

	with open(cert_path) as cf:
		buff = cf.read()
		try:
			cert_content = load_certificate(FILETYPE_PEM,buff)
		except Exception,e:
			try:
				cert_content = load_certificate(FILETYPE_ASN1,buff)
			except Exception,e:
				print e
				return None
		return cert_content

def load_site_cert(site_url):
	m = re.match(urlreg,site_url)
	hostname = m.group(2)
	if m.group(3) == None:
		port = 443
	else:
		port = m.group(3)
		port = int(port[1:len(port)])
	from socket import socket,gethostbyname
	from OpenSSL.SSL import Connection, Context,SSLv3_METHOD,TLSv1_METHOD,TLSv1_1_METHOD,TLSv1_2_METHOD,WantReadError  
	SSL_VER_LIST = [SSLv3_METHOD,TLSv1_METHOD,TLSv1_1_METHOD,TLSv1_2_METHOD]
	for method in SSL_VER_LIST:
		ip=gethostbyname(hostname)
		s = socket()  
		s.connect((ip, port))  
		sslcontext = Context(method)  
		sslcontext.set_timeout(30)  
		c = Connection(sslcontext, s)  
		c.set_connect_state() 
		c.set_tlsext_host_name(hostname)
		proto_v_name = c.get_protocol_version_name()
		print "try to handshake with server: %s using %s" % ( ip , proto_v_name )  
		c.do_handshake()  
		cert = c.get_peer_certificate()
		print cert
		print "issuer: ",cert.get_issuer().get_components()  
		c.shutdown()  
	return 0
	#cert = c.get_peer_certificate()  
	cert_chain = c.get_peer_cert_chain()
	print cert_chain
	for cert in cert_chain:
		print "issuer: ",cert.get_issuer().get_components()  
		print "subject: ",cert.get_subject().get_components()  

	c.shutdown()  
	s.close() 

# 读取证书信息
def read_cert_info(cert_content):
	ret_obj = {
		"err_msg":"",
		"err_code":"0",
		"cert_CN":"",
		"cert_not_after":"",
		"cert_subject_altname":""
	}

	idate_str = cert_content.get_notAfter()
	#idate = datetime.datetime.strptime(idate_str,"%Y%m%d%H%M%S" )
	idate = idate_str[0:14]
	subject = cert_content.get_subject()

	ret_obj["cert_CN"] = subject.CN
	ret_obj["cert_not_after"] = idate
	for x in range(cert_content.get_extension_count()):
		c_ext = cert_content.get_extension(x)
		if c_ext.get_short_name() == "subjectAltName":
			ret_obj["cert_subject_altname"] = c_ext.__str__()
	
	return ret_obj

def main():
	#cert_content = load_local_cert(sys.argv[1])
	#if cert_content:
	#	ret = read_cert_info(cert_content)
	#	for x in ret:
	#		print x,ret[x]
	cert_content = load_site_cert(sys.argv[1])

main()
