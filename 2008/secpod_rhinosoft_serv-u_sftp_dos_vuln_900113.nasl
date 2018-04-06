##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rhinosoft_serv-u_sftp_dos_vuln_900113.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: RhinoSoft Serv-U SFTP Remote Denial of Service Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Remote exploitation will allow attackers to cause the server crash
        or denying the service.

 Impact Level : Application";

tag_affected = "RhinoSoft Serv-U versions prior to 7.2.0.1 on Windows (All).";

tag_insight = "The flaw is due to an error within the logging functionality, when
        creating directories via SFTP or when handling certain SFTP commands.";

tag_solution = "Update to version 7.2.0.1.
 http://www.serv-u.com/dn.asp";
tag_summary = "The host is running RhinoSoft Serv-U SFTP, which is prone to denial
 of service vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900113");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3731");
 script_bugtraq_id(30739);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("Denial of Service");
 script_name("RhinoSoft Serv-U SFTP Remote Denial of Service Vulnerability");
 script_xref(name : "URL" , value : "http://www.serv-u.com/releasenotes/");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31461/");

 script_dependencies("secpod_reg_enum.nasl", "find_service.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139,445);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}


 include("smb_nt.inc");
 include("ftp_func.inc");
 include("secpod_smb_func.inc");

 ftpPort = get_kb_item("Services/ftp");
 if(!ftpPort){
	ftpPort = 21;
 }

 if(!get_port_state(ftpPort)){
	exit(0);
 }

 if("Serv-U" >!< get_ftp_banner(port:ftpPort)){
	exit(0);
 }

 if (!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }
 
 servPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
				"\App Paths\Serv-U", item:"Path");
 if(!servPath){
        exit(0);
 }

 share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:servPath);
 file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:servPath + "\Serv-U.exe");

 name = kb_smb_name();
 domain = kb_smb_domain();
 login = kb_smb_login();
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
 
 prot = smb_neg_prot(soc:soc);
 if(!prot){
	close(soc);
        exit(0);
 }

 r = smb_session_setup(soc:soc, login:login, password:pass,
                       domain:domain, prot:prot);
 if(!r){
	close(soc);
        exit(0);
 }

 uid = session_extract_uid(reply:r);
 if(!uid){
	close(soc);
        exit(0);
 }

 r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
 if(!r){
	close(soc);
        exit(0);
 }

 tid = tconx_extract_tid(reply:r);
 if(!tid){
	close(soc);
        exit(0);
 }

 fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
 if(!fid){
	close(soc);
        exit(0);
 }

 ftpVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod");
 close(soc);

 if(!ftpVer){
	exit(0);
 } 

 if(egrep(pattern:"^([0-6]\..*|7\.([01](\..*)?|2(\.0(\.1)?)?))$", string:ftpVer)){
	security_message(ftpPort);
 }
