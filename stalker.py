#!/usr/bin/env python

import string
import httplib, sys
from socket import *
import re
import getopt
from discovery import *
import hostchecker

print "\n"
print "\t                   __|"
print "\t               __| __|"
print "\t   __|     __| __| __|" 
print "\t   __| __| __| __| __|"
print "\n"
print "\tS   T   A   L   K   E   R"
print "\n"

def usage():
	print "Opcoes de uso:\n"
	print "       -d: Busca orientada pelo dominio ou nome"
	print "       -b: Local de busca ( google, bing, pgp, linkedin, google-profiles, exalead)"
	print "       -s: Iniciar a busca depois do resultado X (padrao 0)"
	print "       -v: Verificar nome do Host via DNS Resolution e buscar atraves do vhosts(basic)"
	print "       -l: Limitar numero de resultados (Recomendavel)"
	print "       -f: Salvar resultado em arquivo XML\n"
	print "\nExemplos:./stalker.py -d yahoo-inc.com -l 500 -b google"
	print "         ./stalker.py -d walmart.com -b pgp"
	print "         ./stalker.py -d petrobras.com.br -l 200 -b linkedin\n"

def start(argv):
	if len(sys.argv) < 4:
		usage()
		sys.exit()
	try :
	       opts, args = getopt.getopt(argv, "l:d:b:s:v:f:")
	except getopt.GetoptError:
  	     	usage()
		sys.exit()
	start=0
	host_ip=[]
	filename=""
	bingapi="yes"
	start=0
	for opt, arg in opts:
		if opt == '-l' :
			limit = int(arg)
		elif opt == '-d':
			word = arg	
		elif opt == '-s':
			start = int(arg)
		elif opt == '-v':
			virtual = arg
		elif opt == '-f':
			filename= arg
		elif opt == '-b':
			engine = arg
			if engine not in ("google", "linkedin", "pgp", "all","google-profiles","exalead","bing","bing_api","yandex"):
				usage()
				print "Motor de busca invalido, utilize: bing, google, linkedin, pgp"
				sys.exit()
			else:
				pass
	if engine == "google":
		print "[-] Pesquisando no Google:"
		search=googlesearch.search_google(word,limit,start)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	if engine == "exalead":
		print "[-] Searching in Exalead:"
		search=exaleadsearch.search_exalead(word,limit,start)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "bing" or engine =="bingapi":	
		print "[-] Pesquisando no Bing:"
		search=bingsearch.search_bing(word,limit,start)
		if engine =="bingapi":
			bingapi="yes"
		else:
			bingapi="no"
		search.process(bingapi)
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "yandex":# Not working yet
		print "[-] Pesquisando no Yandex:"
		search=yandexsearch.search_yandex(word,limit,start)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "pgp":
		print "[-] Pesquisando PGP key server..."
		search=pgpsearch.search_pgp(word)
		search.process()
		all_emails=search.get_emails()
		all_hosts=search.get_hostnames()
	elif engine == "linkedin":
		print "[-] Pesquisando no Linkedin.."
		search=linkedinsearch.search_linkedin(word,limit)
		search.process()
		people=search.get_people()
		print "Usuarios no Linkedin:"
		print "===================="
		for user in people:
			print user
		sys.exit()
	elif engine == "google-profiles":
		print "[-] Pesquisando no Google profiles.."
		search=googlesearch.search_google(word,limit,start)
		search.process_profiles()
		people=search.get_profiles()
		print "Usuarios no Google profiles:"
		print "---------------------------"
		for users in people:
			print users
		sys.exit()
	elif engine == "all":
		print "Full harvest.."
		all_emails=[]
		all_hosts=[]
		virtual = "basic"
		print "[-] Pesquisando no Google..."
		search=googlesearch.search_google(word,limit,start)
		search.process()
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_emails.extend(emails)
		all_hosts.extend(hosts)
		print "[-] Pesquisando PGP Key server..."
		search=pgpsearch.search_pgp(word)
		search.process()
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_hosts.extend(hosts)
		all_emails.extend(emails)
		print "[-] Pesquisando no Bing.."
		bingapi="yes"
		search=bingsearch.search_bing(word,limit,start)
		search.process(bingapi)
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_hosts.extend(hosts)
		all_emails.extend(emails)
		print "[-] Searching in Exalead.."
		search=exaleadsearch.search_exalead(word,limit,start)
		search.process()
		emails=search.get_emails()
		hosts=search.get_hostnames()
		all_hosts.extend(hosts)
		all_emails.extend(emails)

	print "\n[+] Emails encontrados:"
	print " -------------"
	if all_emails ==[]:
		print "Nao foi encontrado nenhum email."
	else:
		for emails in all_emails:
			print emails 
	print "\n[+] Hosts encontrados:"
	print " -----------"
	if all_hosts == []:
		print "Nao foi encontrado nenhum host."
	else:
		full_host=hostchecker.Checker(all_hosts)
		full=full_host.check()
		vhost=[]
		for host in full:
			print host
			ip=host.split(':')[0]
			if host_ip.count(ip.lower()):
				pass
			else:
				host_ip.append(ip.lower())
	if virtual == "basic":
		print "[+] Virtual hosts:"
		print "----------------"
		for l in host_ip:
			search=bingsearch.search_bing(l,limit,start)
 			search.process_vhost()
 			res=search.get_allhostnames()
			for x in res:
				print l+":"+x
				vhost.append(l+":"+x)
				full.append(l+":"+x)
	else:
		pass #Here i need to add explosion mode.
	#Tengo que sacar los TLD para hacer esto.
	recursion=None	
	if recursion:
		limit=300
		start=0
		for word in vhost:
			search=googlesearch.search_google(word,limit,start)
			search.process()
			emails=search.get_emails()
			hosts=search.get_hostnames()
			print emails
			print hosts
	else:
		pass
	if filename!="":
		file = open(filename,'w')
		file.write('<stalker>')
		for x in all_emails:
			file.write('<email>'+x+'</email>')
		for x in all_hosts:
			file.write('<host>'+x+'</host>')
		for x in vhosts:
			file.write('<vhost>'+x+'</vhost>')
		file.write('</stalker>')
		file.close
		print "Resultados salvos em: "+ filename
	else:
		pass

		
if __name__ == "__main__":
        try: start(sys.argv[1:])
	except KeyboardInterrupt:
		print "Busca interrompida pelo usuario!"
	except:
		sys.exit()

