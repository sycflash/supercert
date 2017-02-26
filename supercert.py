#!/usr/bin/python
#coding: utf-8
#
# author: suyanchun
# 2017-2-12

"""
用途1: ./supercert.py 证书文件，验证证书合法性
用途2: ./supercert.py 证书文件 full ，验证证书链完整性，自动补全证书链
用途3: ./supercert.py 站点url，验证站点证书合法性，以及检测站点支持的ssl版本
 依赖: pyopenssl
"""

from urllib import urlopen,urlencode
import datetime
from OpenSSL.crypto import X509,load_certificate,load_pkcs7_data,dump_certificate,FILETYPE_PEM,FILETYPE_ASN1
import re
import sys,os

reload(sys)
sys.setdefaultencoding("UTF-8")

CA_BUNDLE_PATH = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"

urlreg = re.compile(
	r'^((?:http|ftp)s?://)' # http:// or https://
	r'((?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
	r'localhost|' #localhost...
	r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))' # ...or ip
	r'((?::\d+))?' # optional port
	r'(?:/?|[/?]\S+)?$', re.IGNORECASE)

def check_pem_buff(str_buff):
	"""
	- 检查str_buff字符串的内容是不是PEM格式证书
	- 参数 str_buff: 证书内容
	- 返回值: 返回PEM证书链字符串列表，或者None 
	"""
	str_buff = str_buff.strip()
	pem_tag_begin = "-----BEGIN CERTIFICATE-----"
	pem_tag_end = "-----END CERTIFICATE-----"
	first_begin_tag_index = str_buff.find(pem_tag_begin)
	first_end_tag_index = str_buff.find(pem_tag_end)
	if first_begin_tag_index != -1 and first_end_tag_index != -1:
		nindex = first_begin_tag_index
		cert_buff_list = []
		while (nindex < len(str_buff)):
			begin_tag_index = str_buff.find(pem_tag_begin,nindex)
			end_tag_index = str_buff.find(pem_tag_end,nindex)
			nindex = end_tag_index + len(pem_tag_end)
			temp_buff = str_buff[begin_tag_index:nindex]
			cert_buff_list.append(temp_buff)
		return cert_buff_list
	else:
		return None

def load_local_cert(cert_file_path):
	"""
	- 加载本地证书文件，当前支持x509封装的PEM或DER格式证书
	- 参数cert_file_path: 本地证书文件的(相对或绝对)路径
	- 返回值: OpenSSL.crypto.X509 对象列表或者None 
	"""
	if not os.path.isfile(cert_file_path):
		return None

	cert_chain_list = []
	with open(cert_file_path) as cf:
		buff = cf.read()

		chk_buff = check_pem_buff(buff)
		
		"""
		read pem file type
		"""
		if chk_buff != None:
			for x in chk_buff:
				try:
					cert_object = load_certificate(FILETYPE_PEM,x)
				except Exception,e:
					pass
				else:
					cert_chain_list.append(cert_object)

		"""
		read der file type 
		"""
		try:
			cert_object = load_certificate(FILETYPE_ASN1,buff)
		except Exception,e:
			pass
		else:
			cert_chain_list.append(cert_object)

		return cert_chain_list

def load_site_cert(site_url,ssl_version=None):
	"""
	加载站点证书并读取PEM格式证书链，例如https://a.b.com/a
	- 参数 site_url: 携带协议的URL例如https://a.b.com/a
	- 参数 ssl_version: ssl/tls 协议版本(ssl2 ssl3 tls1 tls11 tls12)
	- 返回值: OpenSSL.crypto.X509 对象列表或者None
	"""
	m = re.match(urlreg,site_url)
	hostname = m.group(2)
	if m.group(3) == None:
		port = 443
	else:
		port = m.group(3)
		port = int(port[1:len(port)])
	from socket import socket,gethostbyname
	from OpenSSL.SSL import Connection, Context,TLSv1_METHOD,WantReadError,VERIFY_PEER
	try:
		ip=gethostbyname(hostname)
	except Exception,e:
		print e
		return None
	try:
		s = socket()  
		s.connect((ip, port))  
		sslcontext = Context(TLSv1_METHOD)  
		sslcontext.set_timeout(30)  
		c = Connection(sslcontext, s)  
		c.set_connect_state() 
		c.set_tlsext_host_name(hostname)
		proto_v_name = c.get_protocol_version_name()
		print "try to handshake with server: %s using %s" % ( ip , proto_v_name )  
		c.do_handshake()  
		cert_chain = c.get_peer_cert_chain()
		c.shutdown()  
		s.close() 
	except Exception,e:
		print e
		return None
	else:
		return cert_chain

def read_cert_object(x509_object):
	"""
	- 解析单个x509对象并返回解析结果，自定义字典
	- 参数 x509_object: OpenSSL.crypto.X509 对象
	- 返回值: 自定义字典,包含常见的x509格式信息
	"""
	ret_obj = {}

	idate_str = x509_object.get_notAfter()
	idate_str = idate_str[0:14]
	idate = datetime.datetime.strptime(idate_str,"%Y%m%d%H%M%S" )
	subject = x509_object.get_subject()
	issuer = x509_object.get_issuer()

	ret_obj["subject"] = subject.CN
	ret_obj["notAfter"] = idate
	ret_obj["issuer"] = issuer.CN
	
	for x in range(x509_object.get_extension_count()):
		c_ext = x509_object.get_extension(x)
		if c_ext.get_short_name() == "authorityInfoAccess":
			aia = c_ext.__str__().strip()
			ca_issuer_uri_flag = "CA Issuers - URI:"
			uri_pos = aia.find(ca_issuer_uri_flag)
			if uri_pos != -1:
				ret_obj["issuer_CA_URI"] = aia[(uri_pos+len(ca_issuer_uri_flag)):]
		if c_ext.get_short_name() == "basicConstraints":
			if c_ext.__str__().find("CA:TRUE") == 0:
				ret_obj["is_CA"] = "True"
			else:
				ret_obj["is_CA"] = "False"
		if c_ext.get_short_name() == "subjectAltName":
			ret_obj["subject_AN"] = c_ext.__str__()
	return ret_obj

def verify_chain(cert_list):
	"""
	校验证书链
	- 参数 cert_list: x509对象列表
	"""
	if not os.path.exists(CA_BUNDLE_PATH):
		print "文件不存在:%s" % CA_BUNDLE_PATH
		print "无法进行证书链校验!!!请安装openssl!!!"
		return False
	else:
		with open(CA_BUNDLE_PATH) as ca_bundle_f:
			ca_bundle = load_local_cert(ca_bundle_f.read())
			ca_bundle_objects = [ read_cert_object(co) for co in ca_bundle ]
			ca_bundle_subn = [ sn["subject_CN"] for sn in ca_bundle_objects ]
			
			chain = []
			for x in cert_list:
				xo = read_cert_object(x)
				xo["verified"] = False
				chain.append(xo)

			issuer_last = ""
			subject_last = ""
			veri_depth = 0
			for y in chain:
				y["veri_depth"] = veri_depth
				if subject_last == "":
					issuer_last = y["issuer"]
					subject_last = y["subject"]
				if issuer_last == y["subject"]:
					y["verified"] = True
				if y["subject"] in ca_bundle_subn:
					return True
					break
			
			return False

def main():
	if re.match(urlreg,sys.argv[1]):
		clist = load_site_cert(sys.argv[1])
	else:
		clist = load_local_cert(sys.argv[1])

	if clist:
		print "Certificate Chain:"
		for cobject in clist:
			print "-"*40
			ret = read_cert_object(cobject)
			for x in ret:
				print x,":",ret[x]
main()
