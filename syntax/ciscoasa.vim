" 
" Vim syntax file
" Language: Cisco ASA configuration files
" Maintainer: Bertho Stultiens <bst@logiva.dk>
" Version: 1.0.0
" Last Modification: 13-Apr-2010
" 
" 

if version < 600
	syntax clear
elseif exists("b:current_syntax")
	finish
endif

syntax case ignore
setlocal iskeyword+=/
setlocal iskeyword+=:
setlocal iskeyword+=.
setlocal iskeyword+=-

syntax match asa_ipnum /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ contained
syntax match asa_iphost /\(\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\|\([a-z0-9_-]\{1,64}\(\.[a-z0-9_-]\{2,64}\)*\.\?\)/ contained
syntax match asa_ipnum_mask /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ contained
syntax region asa_comment start=// end=//
syntax match asa_comment /^\s*!.*/
syntax match asa_string /.*/ contained
syntax match asa_text /\S\+/ contained
syntax match asa_word /\w\+/ contained
syntax match asa_keyword /\w\+/ contained
syntax match asa_ifname /\w\+/ contained
syntax match asa_integer /\d\+/ contained
syntax match asa_proto /tcp\|udp\|icmp/ contained

syntax keyword asa_prefix no def[ault] sh[ow] cl[ear]

syntax keyword asa_boot boot nextgroup=asa_boot_system skipwhite
syntax keyword asa_boot_system sys[tem] nextgroup=asa_string skipwhite

syntax keyword asa_description desc[ription] nextgroup=asa_string skipwhite
syntax keyword asa_domain_name domain-n[ame] nextgroup=asa_string skipwhite
syntax keyword asa_hostname hostn[ame] nextgroup=asa_string skipwhite
syntax keyword asa_management_only management-o[nly]
syntax keyword asa_nameif namei[f] nextgroup=asa_ifname skipwhite
syntax keyword asa_security_level security-l[evel] nextgroup=asa_integer skipwhite
syntax keyword asa_shutdown shut[down]
syntax keyword asa_vlan vla[n] nextgroup=asa_integer skipwhite

syntax keyword asa_various nat-c[ontrol] names

syntax keyword asa_acg access-gr[oup] nextgroup=asa_acg_acl skipwhite
syntax match asa_acg_acl /\w\+/ nextgroup=asa_acg_io skipwhite contains=asa_word contained
syntax keyword asa_acg_io in out nextgroup=asa_acg_if skipwhite contained
syntax keyword asa_acg_if int[erface] nextgroup=asa_acg_ifname skipwhite contained
syntax match asa_acg_ifname /\w\+/ contains=asa_ifname contained

syntax keyword asa_acl access-l[ist] nextgroup=asa_aclid skipwhite
syntax match asa_aclid /\w\+/ nextgroup=asa_acl_line,asa_acl_ext,asa_acl_pd skipwhite contains=asa_word contained
syntax keyword asa_acl_line li[ne] nextgroup=asa_acl_linenr skipwhite contained
syntax match asa_acl_linenr /\d\+/ nextgroup=asa_acl_ext,asa_acl_pd skipwhite contains=asa_integer contained
syntax keyword asa_acl_ext ext[ended] nextgroup=asa_acl_pd skipwhite contained
syntax keyword asa_acl_pd perm[it] den[y] nextgroup=asa_acl_proto,asa_acl_protog skipwhite contained
syntax keyword asa_acl_pd rem[ark] nextgroup=asa_acl_rem skipwhite contained
syntax match asa_acl_rem /.*/ contained
syntax keyword asa_acl_proto ip tcp udp icmp nextgroup=asa_acl_src skipwhite contained
syntax match asa_acl_proto /\d\+/ nextgroup=asa_acl_src skipwhite contains=asa_integer contained
syntax keyword asa_acl_protog object-group nextgroup=asa_acl_protogid skipwhite contained
syntax match asa_acl_protogid /\w\+/ nextgroup=asa_acl_src skipwhite contains=asa_word contained
syntax match asa_acl_src /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_acl_sport,asa_acl_dst skipwhite contains=asa_ipnum_mask contained
syntax match asa_acl_src /host\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_acl_sport,asa_acl_dst skipwhite contains=asa_ipnum contained
syntax match asa_acl_src /any/ nextgroup=asa_acl_sport,asa_acl_dst skipwhite contains=asa_ipnum contained
syntax keyword asa_acl_src object-group nextgroup=asa_acl_sogid skipwhite contained
syntax match asa_acl_sogid /\w\+/ nextgroup=asa_acl_sport,asa_acl_dst skipwhite contains=asa_word contained
syntax keyword asa_acl_sport lt gt eq neq nextgroup=asa_acl_sportid skipwhite contained
syntax keyword asa_acl_sport ran[ge] nextgroup=asa_acl_sportr skipwhite contained
syntax match asa_acl_sportid /\w\+/ nextgroup=asa_acl_dst skipwhite contains=asa_word contained
syntax match asa_acl_sportr /\d\+\s\+\d\+/ nextgroup=asa_acl_dst skipwhite contains=asa_integer contained
syntax match asa_acl_dst /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_acl_dport,asa_acl_icmp,asa_acl_trail,asa_acl_acct skipwhite contains=asa_ipnum_mask contained
syntax match asa_acl_dst /host\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_acl_dport,asa_acl_icmp,asa_acl_trail,asa_acl_acct skipwhite contains=asa_ipnum contained
syntax match asa_acl_dst /any/ nextgroup=asa_acl_dport,asa_acl_icmp,asa_acl_trail,asa_acl_acct skipwhite contains=asa_ipnum contained
syntax keyword asa_acl_dst object-group nextgroup=asa_acl_dogid skipwhite contained
syntax match asa_acl_dogid /\w\+/ nextgroup=asa_acl_dport,asa_acl_icmp,asa_acl_trail,asa_acl_acct skipwhite contains=asa_word contained
syntax keyword asa_acl_dport lt gt eq neq nextgroup=asa_acl_dportid skipwhite contained
syntax keyword asa_acl_dport ran[ge] nextgroup=asa_acl_dportr skipwhite contained
syntax match asa_acl_dportid /\w\+/ nextgroup=asa_acl_trail,asa_acl_acct skipwhite contains=asa_word contained
syntax match asa_acl_dportr /\d\+\s\+\d\+/ nextgroup=asa_acl_trail,asa_acl_acct skipwhite contains=asa_integer 
syntax keyword asa_acl_icmp al[ternate-address] co[nversion-error] echo echo-[reply] information-rep[ly] asa_acl_icmp information-req[uest] mask-rep[ly] mask-req[uest] mo[bile-redirect] pa[rameter-problem] asa_acl_icmp re[direct] router-a[dvertisement] router-s[olicitation] so[urce-quench] time-e[xceeded] asa_acl_icmp timestamp-rep[ly] timestamp-req[uest] tr[aceroute] un[reachable] nextgroup=asa_acl_trail,asa_acl_acct skipwhite contained
syntax match asa_acl_icmp /\d\+/ nextgroup=asa_acl_trail,asa_acl_acct skipwhite contains=asa_integer contained
syntax keyword asa_acl_trail lo[g] nextgroup=asa_acl_loglvl,asa_acl_log,asa_acl_acct skipwhite contained
syntax match asa_acl_loglvl /[0-7]/ nextgroup=asa_acl_log,asa_acl_acct skipwhite contains=asa_integer contained
syntax keyword asa_acl_log interv[al] nextgroup=asa_acl_logiv skipwhite contained
syntax match asa_acl_logiv /\d\+/ nextgroup=asa_acl_acct contains=asa_integer skipwhite contained
syntax keyword asa_acl_log dis[able] def[ault] contained
syntax keyword asa_acl_acct in[active] contained
syntax keyword asa_acl_acct time-ra[nge] nextgroup=asa_word skipwhite contained

syntax keyword asa_arp arp nextgroup=asa_arp_timeout,asa_arp_if skipwhite
syntax keyword asa_arp_timeout timeo[ut] nextgroup=asa_integer skipwhite contained
syntax match asa_arp_if /\w\+/ nextgroup=asa_arp_ip skipwhite contains=asa_ifname contained
syntax match asa_arp_ip /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_arp_mac skipwhite contains=asa_ipnum contained
syntax match asa_arp_mac /\x\{4}\.\x\{4}\.\x\{4}/ contained

syntax keyword asa_crypto cry[pto] nextgroup=asa_crypto_ipsec,asa_crypto_map,asa_crypto_isakmp skipwhite
syntax keyword asa_crypto_ipsec ips[ec] nextgroup=asa_crypto_ipsec_ts,asa_crypto_dfbit,asa_crypto_frag,asa_crypto_ipsec_sa skipwhite contained
syntax keyword asa_crypto_ipsec_ts trans[form-set] nextgroup=asa_crypto_ipsec_tsname skipwhite contained
syntax match asa_crypto_ipsec_tsname /\w\+/ nextgroup=asa_crypto_ipsec_tscrypt skipwhite contains=asa_word contained
syntax keyword asa_crypto_ipsec_tscrypt esp-des esp-3des esp-aes esp-aes-192 esp-aes-256 nextgroup=asa_crypto_ipsec_tshmac skipwhite contained
syntax keyword asa_crypto_ipsec_tshmac esp-sha-[hmac] esp-md5-[hmac] contained
syntax keyword asa_crypto_ipsec_sa security-a[ssociation] nextgroup=asa_crypto_ipsec_salife,asa_crypto_ipsec_sarep skipwhite contained
syntax keyword asa_crypto_ipsec_salife lifet[ime] nextgroup=asa_crypto_ipsec_salifet skipwhite contained
syntax keyword asa_crypto_ipsec_salifet sec[onds] kil[obytes] nextgroup=asa_integer skipwhite contained
syntax keyword asa_crypto_ipsec_sarep re[play] nextgroup=asa_crypto_ipsec_salrepdis,asa_crypto_ipsec_sarepw skipwhite contained
syntax keyword asa_crypto_ipsec_sarepdis dis[able] contained
syntax keyword asa_crypto_ipsec_sarepw win[dow-size] nextgroup=asa_integer skipwhite contained
syntax keyword asa_crypto_dfbit df-[bit] nextgroup=asa_crypto_dfbitval skipwhite contained
syntax keyword asa_crypto_dfbitval c[lear-df] s[et-df] c[opy-df] nextgroup=asa_ifname skipwhite contained
syntax keyword asa_crypto_frag frag[mentation] nextgroup=asa_crypto_fragtime skipwhite contained
syntax keyword asa_crypto_fragtime b[efore-encryption] a[fter-encryption] nextgroup=asa_ifname skipwhite contained
syntax keyword asa_crypto_map ma[p] nextgroup=asa_crypto_mapname skipwhite contained
syntax match asa_crypto_mapname /\w\+/ nextgroup=asa_crypto_mapid,asa_crypto_mapif skipwhite contains=asa_word contained
syntax match asa_crypto_mapid /\d\+/ nextgroup=asa_crypto_map_parms skipwhite contains=asa_integer contained
syntax keyword asa_crypto_mapif int[terface] nextgroup=asa_ifname skipwhite contained
syntax keyword asa_crypto_map_parms mat[ch] nextgroup=asa_crypto_map_match skipwhite contained
syntax keyword asa_crypto_map_parms se[t] nextgroup=asa_crypto_map_set skipwhite contained
syntax keyword asa_crypto_map_match add[ress] nextgroup=asa_word skipwhite contained
syntax keyword asa_crypto_map_set co[nnection-type] nextgroup=asa_crypto_map_set_con skipwhite contained
syntax keyword asa_crypto_map_set in[heritance] nextgroup=asa_crypto_map_set_inh skipwhite contained
syntax keyword asa_crypto_map_set na[t-t-disable] re[verse-route] contained
syntax keyword asa_crypto_map_set pe[er] nextgroup=asa_iphost skipwhite contained
syntax keyword asa_crypto_map_set pf[s] nextgroup=asa_crypto_map_set_pfs skipwhite contained
syntax keyword asa_crypto_map_set ph[ase1-mode] nextgroup=asa_crypto_map_set_ph1 skipwhite contained
syntax keyword asa_crypto_map_set se[curity-association] nextgroup=asa_crypto_ipsec_salife skipwhite contained
syntax keyword asa_crypto_map_set tra[nsform-set] nextgroup=asa_word skipwhite contained
syntax keyword asa_crypto_map_set tru[stpoint] nextgroup=asa_crypto_map_set_tp skipwhite contained
syntax keyword asa_crypto_map_set_con an[swer-only] or[iginate-only] bi[directional] contained
syntax keyword asa_crypto_map_set_inh da[ta] ru[le] contained
syntax keyword asa_crypto_map_set_pfs group1 group2 group5 contained
syntax keyword asa_crypto_map_set_ph1 group1 group2 group5 ma[in] ag[gressive] contained
syntax match asa_crypto_map_set_tp /\w\+/ nextgroup=asa_crypto_map_set_tpc skipwhite contains=asa_word contained
syntax keyword asa_crypto_map_set_tpc ch[ain] contained
syntax keyword asa_crypto_isakmp isa[kmp] nextgroup=asa_crypto_isakmp_arg skipwhite contained
syntax keyword asa_crypto_isakmp_arg en[able] nextgroup=asa_ifname skipwhite contained
syntax keyword asa_crypto_isakmp_arg pol[icy] nextgroup=asa_integer skipwhite contained

syntax keyword asa_crypto_isakmp_auth authentication nextgroup=asa_crypto_isakmp_autht skipwhite
syntax keyword asa_crypto_isakmp_autht cra[ck] pre[-share] rsa[-sig] contained
syntax keyword asa_crypto_isakmp_enc encryption nextgroup=asa_crypto_isakmp_enct skipwhite
syntax keyword asa_crypto_isakmp_enct aes aes-192 aes-256 des 3des comtained
syntax keyword asa_crypto_isakmp_hash hash nextgroup=asa_crypto_isakmp_hashname skipwhite
syntax keyword asa_crypto_isakmp_hashname sha md5 contained
syntax keyword asa_crypto_isakmp_grp group nextgroup=asa_integer skipwhite
syntax match asa_crypto_isakmp_grpid /[125]/ contains=asa_integer contained
syntax keyword asa_crypto_isakmp_life lifetime nextgroup=asa_integer skipwhite

syntax keyword asa_isakmp isa[kmp] nextgroup=asa_isakmp_ka skipwhite
syntax keyword asa_isakmp_ka keep[alive] nextgroup=asa_isakmp_kaarg skipwhite contained
syntax keyword asa_isakmp_kaarg thres[hold] nextgroup=asa_isakmp_ka_n skipwhite contained
syntax keyword asa_isakmp_kaarg ret[ry] nextgroup=asa_isakmp_ka_n skipwhite contained
syntax keyword asa_isakmp_kaarg dis[able] nextgroup=asa_isakmp_ka skipwhite contained
syntax match asa_isakmp_ka_n /\d\+/ nextgroup=asa_isakmp_kaarg skipwhite contains=asa_integer contained

syntax keyword asa_login ssh teln[et] cons[ole] nextgroup=asa_login_arg skipwhite
syntax keyword asa_login_arg ver[sion] tim[eout] nextgroup=asa_integer skipwhite contained
syntax match asa_login_arg /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_ifname skipwhite contains=asa_ipnum_mask contained

syntax keyword asa_enable ena[ble] nextgroup=asa_enable_pass skipwhite
syntax keyword asa_enable_pass pass[word] nextgroup=asa_enable_password skipwhite contained
syntax match asa_enable_password /\S\+/ nextgroup=asa_enable_encrypted skipwhite contained
syntax keyword asa_enable_encrypted encr[ypted] contained

syntax keyword asa_ftp ftp nextgroup=asa_ftp_mode skipwhite
syntax keyword asa_ftp_mode mo[de] nextgroup=asa_ftp_mode_passive skipwhite
syntax keyword asa_ftp_mode_passive pass[ive]

syntax keyword asa_interface int[erface] nextgroup=asa_interface_name,asa_ifname skipwhite
syntax match asa_interface_name /\(Gigabit|Fast\)\?Ethernet\d\+\/\d\+\(\/\d\+\)\?\(\.\d\+\)\?/ contained
syntax match asa_interface_name /Management\d\+\/\d\+/ contained
"syntax match asa_interface_name /Loopback\(\d\+\)/ contained
"syntax match asa_interface_name /Null0/ contained

syntax keyword asa_ip ip nextgroup=asa_ip_address skipwhite
syntax keyword asa_ip_address addr[ess] nextgroup=asa_ipnum_mask skipwhite

syntax keyword asa_global glob[al] nextgroup=asa_global_if skipwhite
syntax match asa_global_if /(\w\+)/ nextgroup=asa_global_id skipwhite contains=asa_ifname contained
syntax match asa_global_id /\d\+/ nextgroup=asa_ipnum skipwhite contains=asa_integer contained

syntax keyword asa_logging logg[ing] nextgroup=asa_log_enable,asa_log_timestamp,asa_log_buffer_size,asa_log_buffered,asa_log_facility,asa_log_host,asa_log_devid skipwhite
syntax keyword asa_log_enable ena[ble] stand[by] emb[lem] contained
syntax keyword asa_log_timestamp times[tamp] contained
syntax keyword asa_log_buffer_size buffer-[size] nextgroup=asa_integer skipwhite contained
syntax keyword asa_log_buffered buffere[d] hist[ory] mon[itor] ma[il] tra[p] nextgroup=asa_integer,asa_log_levelname skipwhite contained
syntax keyword asa_log_levelname eme[rgencies] al[erts] cri[tical] err[ors] warn[ings] noti[fications] info[rmational] deb[ugging] contained
syntax keyword asa_log_facility faci[lity] nextgroup=asa_integer skipwhite contained
syntax keyword asa_log_host host nextgroup=asa_log_hostif skipwhite contained
syntax match asa_log_hostif /\w\+/ nextgroup=asa_ipnum skipwhite contains=asa_ifname contained
syntax keyword asa_log_devid device-[id] nextgroup=asa_log_devid_tag,asa_log_devid_str,asa_log_devid_ip skipwhite contained
syntax keyword asa_log_devid_tag con[text-name] ho[stname] contained
syntax keyword asa_log_devid_str str[ing] nextgroup=asa_string skipwhite contained
syntax keyword asa_log_devid_ip ip[address] nextgroup=asa_ifname skipwhite contained

syntax keyword asa_mtu mtu nextgroup=asa_mtu_if skipwhite
syntax match asa_mtu_if /\w\+/ nextgroup=asa_integer skipwhite contains=asa_ifname contained

syntax keyword asa_nat nat nextgroup=asa_nat_if skipwhite
syntax match asa_nat_if /(\w\+)/ nextgroup=asa_nat_id skipwhite contains=asa_ifname contained
syntax match asa_nat_id /\d\+/ nextgroup=asa_nat_acl,asa_ipnum_mask skipwhite contained
syntax keyword asa_nat_acl access-l[ist] nextgroup=asa_nat_aclname skipwhite contained
syntax match asa_nat_ipnum /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_nat_outside skipwhite contains=asa_ipnum_mask contained
syntax match asa_nat_aclname /\w\+/ nextgroup=asa_nat_outside skipwhite contains=asa_word contained
syntax keyword asa_nat_outside out[side] contained

syntax keyword asa_ntp ntp nextgroup=asa_ntp_srv skipwhite
syntax keyword asa_ntp_srv ser[ver] nextgroup=asa_ntp_ip skipwhite contained
syntax match asa_ntp_ip /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_ntp_opt skipwhite contains=asa_ipnum contained
syntax keyword asa_ntp_opt sou[rce] ke[y] nextgroup=asa_ntp_src skipwhite contained
syntax keyword asa_ntp_opt pref[er] contained
syntax match asa_ntp_src /\w\+/ nextgroup=asa_ntp_opt skipwhite contains=asa_word contained

syntax keyword asa_og object-group nextgroup=asa_ogt skipwhite
syntax keyword asa_ogt prot[ocol] net[work] icmp[-type] nextgroup=asa_word skipwhite contained
syntax keyword asa_ogt ser[vice] nextgroup=asa_ogsn skipwhite contained
syntax match asa_ogsn /\w\+/ nextgroup=asa_ogs skipwhite contains=asa_word contained
syntax keyword asa_ogs tcp ud[p] tcp-[udp] contained
syntax keyword asa_oggo group-ob[ject] nextgroup=asa_word skipwhite
syntax keyword asa_ogpo protocol-ob[ject] nextgroup=asa_ogpo_proto skipwhite
syntax keyword asa_ogpo_proto ip tcp udp icmp contained
syntax match asa_ogpo_proto /\d\+/ contains=asa_integer contained
syntax keyword asa_ogno network-ob[ject] nextgroup=asa_ogno_no skipwhite
syntax keyword asa_ogno_no ho[st] nextgroup=asa_iphost skipwhite contained
syntax match asa_ogno_no /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ contains=asa_ipnum_mask contained
syntax keyword asa_ogso port-ob[ject] nextgroup=asa_ogso_eq skipwhite
syntax keyword asa_ogso_eq eq nextgroup=asa_ogso_port skipwhite contained
syntax keyword asa_ogso_eq ra[nge] nextgroup=asa_ogso_portr skipwhite contained
syntax keyword asa_ogso_port bgp biff discard chargen bootpc domain cmd bootps echo daytime dnsix pim-auto-rp exec nameserver sunrpc finger mobile-ip syslog ftp netbios-ns tacacs ftp-data netbios-dgm talk gopher ntp ident rip irc snmp h323 snmptrap hostname tftp http time klogin who kshell xdmcp login isakmp lpd nntp pop2 pop3 smtp sqlnet telnet uucp whois www contained
syntax match asa_ogso_port /\d\+/ contains=asa_integer contained
syntax match asa_ogso_portr /\d\+\s\+\d\+/ contains=asa_integer contained

syntax keyword asa_pager pag[er] nextgroup=asa_pager_lines,asa_pager_n skipwhite
syntax keyword asa_pager_lines li[nes] nextgroup=asa_pager_n skipwhite contained
syntax match asa_pager_n /\d\+/ contains=asa_integer contained

syntax keyword asa_passwd passwd nextgroup=asa_enable_password skipwhite

syntax keyword asa_psk pre-s[hared-key] nextgroup=asa_psk_str skipwhite
syntax match asa_psk_str /\S\+/ contains=asa_string contained

syntax keyword asa_route route nextgroup=asa_route_ifname skipwhite
syntax match asa_route_ifname /\w\+/ nextgroup=asa_route_ipgw skipwhite contains=asa_ifname contained
syntax match asa_route_ipgw /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\(\s\+\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\)\{2}/ nextgroup=asa_integer skipwhite contains=asa_ipnum contained

syntax keyword asa_snmp_server snmp-se[rver] nextgroup=asa_snmp_server_arg skipwhite
syntax keyword asa_snmp_server_arg loc[ation] con[tact] comm[unity] nextgroup=asa_string skipwhite contained

syntax keyword asa_static stati[c] nextgroup=asa_static_ifs skipwhite
syntax match asa_static_ifs /(\w\+,\w\+)/ nextgroup=asa_static_mappedip,asa_static_mappedint,asa_static_patproto skipwhite contains=asa_ifname contained
syntax keyword asa_static_patproto udp tcp nextgroup=asa_static_mappedip,asa_static_mappedint skipwhite contained
syntax match asa_static_mappedip /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_static_mapport,asa_static_realip,asa_static_realacl skipwhite contains=asa_ipnum contained
syntax match asa_static_mapport /\w\+/ nextgroup=asa_static_realip,asa_static_realacl contains=asa_word skipwhite contained
syntax keyword asa_static_mappedint int[erface] nextgroup=asa_static_realip,asa_static_realacl skipwhite contained
syntax match asa_static_realip /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_static_patport,asa_static_mask,asa_static_trail1 skipwhite contains=asa_ipnum contained
syntax match asa_static_patport /\w\+/ nextgroup=asa_static_mask,asa_static_trail1,asa_static_trail2,asa_static_trail3 contains=asa_word skipwhite contained
syntax keyword asa_static_mask netm[ask] nextgroup=asa_static_netmask skipwhite contained
syntax match asa_static_netmask /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}/ nextgroup=asa_static_trail1,asa_static_trail2,asa_static_trail3 skipwhite contains=asa_ipnum contained
syntax keyword asa_static_realacl access-l[ist] nextgroup=asa_static_realaclname skipwhite contained
syntax match asa_static_realaclname /\w\+/ nextgroup=asa_static_trail1,asa_static_trail2,asa_static_trail3 skipwhite contains=asa_word contained
syntax keyword asa_static_trail1 dns nextgroup=asa_static_trail2,asa_static_trail3 skipwhite contained
syntax match asa_static_trail2 /\(tcp\|udp\)\s\+\d\+/ nextgroup=asa_static_trail2,asa_static_trail3 skipwhite contains=asa_proto,asa_integer contained
syntax keyword asa_static_trail3 nora[ndomseq] nextgroup=asa_static_trail4 skipwhite contained
syntax keyword asa_static_trail4 nail[ed] contained

syntax keyword asa_timeout timeo[ut] nextgroup=asa_timeout_key skipwhite
syntax keyword asa_timeout_key xla[te] conn half-[closed] udp icmp sunrpc h323 h225 mgcp mgcp-[pat] sip sip_[media] sip-i[nvite] sip-d[isconnect] sip-prov[isional-media] sip-prox[y-reassembly] tcp-pr[oxy-reassembly] uauth nextgroup=,asa_timeout_timespec skipwhite contained
syntax match asa_timeout_timespec /\d\{1,2}:\d\{1,2}:\d\{1,2}/ nextgroup=asa_timeout_key,asa_timeout_absolute skipwhite contained
syntax keyword asa_timeout_absolute abs[olute] nextgroup=asa_timeout_key skipwhite contained

syntax keyword asa_tungr tunnel-[group] nextgroup=asa_tungr_name,asa_tungr_ip skipwhite
syntax match asa_tungr_ip /\d\{1,3}\.\d\{1,3}\.\d\{1,3}\.\d\{1,3}\|\w\+/ nextgroup=asa_tungr_type,asa_tungr_attr skipwhite contains=asa_ipnum contained
syntax keyword asa_tungr_type ty[pe] nextgroup=asa_tungr_typename skipwhite contained
syntax keyword asa_tungr_typename rem[ote-access] ipsec-l[2l] ipsec-ra webvpn contained
syntax keyword asa_tungr_attr general-[attributes] ipsec-[attributes] webvpn-[attributes] ppp-[attributes] contained

syntax keyword asa_usr usern[ame] nextgroup=asa_usr_name skipwhite
syntax match asa_usr_name /\w\+/ nextgroup=asa_usr_pw skipwhite contains=asa_word contained
syntax keyword asa_usr_pw nopas[sword] nextgroup=asa_usr_priv skipwhite contained
syntax keyword asa_usr_pw pas[sword] nextgroup=asa_usr_pass skipwhite contained
syntax match asa_usr_pass /\S\+/ nextgroup=asa_usr_pwopt skipwhite contains=asa_text contained
syntax keyword asa_usr_pwopt ms[chap] enc[rypted] nt-[encrypted] nextgroup=asa_usr_priv skipwhite contained
syntax keyword asa_usr_priv priv[ilege] nextgroup=asa_integer skipwhite contained

" Define the default hightlighting.
" For version 5.7 and earlier: only when not done already
" For version 5.8 and later: only when an item doesn't have highlighting yet
if version >= 508 || !exists("did_ciscoasa_syn_inits")
	if version < 508
		let did_ciscoasa_syn_inits = 1
		command -nargs=+ HiLink hi link <args>
	else
		command -nargs=+ HiLink hi def link <args>
	endif

	HiLink asa_prefix Tag
	HiLink asa_boot keyword
	HiLink asa_boot_system keyword
	HiLink asa_interface Keyword
	HiLink asa_interface_name String
	HiLink asa_description keyword
	HiLink asa_domain_name keyword
	HiLink asa_acg Keyword
	HiLink asa_acg_io Keyword
	HiLink asa_acg_if Keyword
	HiLink asa_acl Keyword
	HiLink asa_acl_line Keyword
	HiLink asa_acl_ext Keyword
	HiLink asa_acl_pd Keyword
	HiLink asa_acl_proto Type
	HiLink asa_acl_protog Keyword
	HiLink asa_acl_src Keyword
	HiLink asa_acl_sport Keyword
	HiLink asa_acl_dst Keyword
	HiLink asa_acl_dport Keyword
	HiLink asa_acl_icmp Type
	HiLink asa_acl_trail Keyword
	HiLink asa_acl_log Keyword
	HiLink asa_acl_acct Keyword
	HiLink asa_acl_rem Comment
	HiLink asa_arp keyword
	HiLink asa_arp_timeout keyword
	HiLink asa_arp_mac String
	HiLink asa_crypto Keyword
	HiLink asa_crypto_ipsec Keyword
	HiLink asa_crypto_ipsec_ts Keyword
	HiLink asa_crypto_ipsec_tscrypt Type
	HiLink asa_crypto_ipsec_tshmac Type
	HiLink asa_crypto_ipsec_sa Keyword
	HiLink asa_crypto_ipsec_salife Keyword
	HiLink asa_crypto_ipsec_salifet Keyword
	HiLink asa_crypto_ipsec_sarep Keyword
	HiLink asa_crypto_ipsec_sarepdis Keyword
	HiLink asa_crypto_ipsec_sarepw Keyword
	HiLink asa_crypto_dfbit Keyword
	HiLink asa_crypto_dfbitval Keyword
	HiLink asa_crypto_frag Keyword
	HiLink asa_crypto_fragtime Keyword
	HiLink asa_crypto_map Keyword
	HiLink asa_crypto_mapif Keyword
	HiLink asa_crypto_map_parms Keyword
	HiLink asa_crypto_map_match Keyword
	HiLink asa_crypto_map_set Keyword
	HiLink asa_crypto_map_set_con Keyword
	HiLink asa_crypto_map_set_inh Keyword
	HiLink asa_crypto_map_set_pfs Keyword
	HiLink asa_crypto_map_set_ph1 Keyword
	HiLink asa_crypto_map_set_tpc Keyword
	HiLink asa_crypto_isakmp Keyword
	HiLink asa_crypto_isakmp_arg Keyword
	HiLink asa_crypto_isakmp_auth Keyword
	HiLink asa_crypto_isakmp_autht Type
	HiLink asa_crypto_isakmp_enc Keyword
	HiLink asa_crypto_isakmp_enct Type
	HiLink asa_crypto_isakmp_hash Keyword
	HiLink asa_crypto_isakmp_hashname Type
	HiLink asa_crypto_isakmp_grp Keyword
	HiLink asa_crypto_isakmp_life Keyword
	HiLink asa_ftp keyword
	HiLink asa_ftp_mode keyword
	HiLink asa_ftp_mode_passive keyword
	HiLink asa_enable keyword
	HiLink asa_enable_pass keyword
	HiLink asa_enable_password String
	HiLink asa_enable_encrypted keyword
	HiLink asa_global keyword
	HiLink asa_hostname keyword
	HiLink asa_ip keyword
	HiLink asa_ip_address keyword
	HiLink asa_isakmp Keyword
	HiLink asa_isakmp_ka Keyword
	HiLink asa_isakmp_kaarg Keyword
	HiLink asa_logging keyword
	HiLink asa_log_enable keyword
	HiLink asa_log_timestamp keyword
	HiLink asa_log_buffer_size keyword
	HiLink asa_log_buffered keyword
	HiLink asa_log_levelname String
	HiLink asa_log_facility Keyword
	HiLink asa_log_host Keyword
	HiLink asa_log_devid Keyword
	HiLink asa_log_devid_tag Keyword
	HiLink asa_log_devid_str Keyword
	HiLink asa_log_devid_ip Keyword
	HiLink asa_login Keyword
	HiLink asa_login_arg Keyword
	HiLink asa_management_only keyword
	HiLink asa_mtu keyword
	HiLink asa_nameif keyword
	HiLink asa_nat keyword
	HiLink asa_nat_id Number
	HiLink asa_nat_acl keyword
	HiLink asa_nat_outside keyword
	HiLink asa_ntp Keyword
	HiLink asa_ntp_srv Keyword
	HiLink asa_ntp_opt Keyword
	HiLink asa_og Keyword
	HiLink asa_ogt Keyword
	HiLink asa_ogs Keyword
	HiLink asa_oggo Keyword
	HiLink asa_ogpo Keyword
	HiLink asa_ogpo_proto Type
	HiLink asa_ogno Keyword
	HiLink asa_ogno_no Keyword
	HiLink asa_ogso Keyword
	HiLink asa_ogso_eq Keyword
	HiLink asa_ogso_port Type
	HiLink asa_pager keyword
	HiLink asa_pager_lines keyword
	HiLink asa_passwd keyword
	HiLink asa_psk keyword
	HiLink asa_route keyword
	HiLink asa_security_level keyword
	HiLink asa_shutdown keyword
	HiLink asa_snmp_server keyword
	HiLink asa_snmp_server_arg keyword
	HiLink asa_static Keyword
	HiLink asa_static_patproto Keyword
	HiLink asa_static_mappedint Keyword
	HiLink asa_static_realacl Keyword
	HiLink asa_static_mask Keyword
	HiLink asa_static_trail1 Keyword
	HiLink asa_static_trail2 Keyword
	HiLink asa_static_trail3 Keyword
	HiLink asa_static_trail4 Keyword
	HiLink asa_timeout keyword
	HiLink asa_timeout_key String
	HiLink asa_timeout_timespec Type
	HiLink asa_timeout_absolute keyword
	HiLink asa_tungr Keyword
	HiLink asa_tungr_ip String
	HiLink asa_tungr_type Keyword
	HiLink asa_tungr_typename Keyword
	HiLink asa_tungr_attr Keyword
	HiLink asa_usr Keyword
	HiLink asa_usr_pw Keyword
	HiLink asa_usr_pwopt Keyword
	HiLink asa_usr_priv Keyword
	HiLink asa_vlan keyword
	HiLink asa_various keyword
	HiLink asa_iphost Type
	HiLink asa_ipnum Type
	HiLink asa_ipnum_mask Type
	HiLink asa_ipnum_route Type
	HiLink asa_string String
	HiLink asa_text String
	HiLink asa_word String
	HiLink asa_keyword Keyword
	HiLink asa_ifname Type
	HiLink asa_comment Comment
	HiLink asa_integer Number
	HiLink asa_proto Keyword

	delcommand HiLink
endif
let b:current_syntax = "ciscoasa"

" vim:ts=4
