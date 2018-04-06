##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_rhinosoft_serv-u_dir_trav_and_dos_vuln_900149.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Serv-U File Renaming Directory Traversal and 'STOU' DoS Vulnerabilities
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

tag_impact = "Successful exploitation allows an attacker to write arbitrary files to 
  locations outside of the application's current directory, and deny the service.
  Impact Level : Application";

tag_solution = "Upgrade to RhinoSoft Serv-U FTP Server 10 or later,
  For updates refer to http://www.serv-u.com/dn.asp";

tag_affected = "RhinoSoft Serv-U FTP Server 7.3.0.0 and prior";


tag_summary = "The host is running Serv-U FTP Server, which is prone to Directory
  Traversal and Denial of Service Vulnerabilities. 

  The flaws are due to,
  - error in handling 'STOU' FTP command. It can exhaust available CPU
    resources when exploited through a specially crafted argument vaule.
  - input validation error in the FTP service when renaming files which can be
    exploited to overwrite or rename files via directory traversal attacks.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900149");
  script_version("$Revision: 9349 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2008-10-14 16:57:31 +0200 (Tue, 14 Oct 2008)");
  script_bugtraq_id(31563);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_name("Serv-U File Renaming Directory Traversal and 'STOU' DoS Vulnerabilities");

  script_dependencies("secpod_reg_enum.nasl", "find_service.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445, "Services/ftp", 21);
  script_xref(name : "URL" , value : "http://milw0rm.com/exploits/6660");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/32150/");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/45653");
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
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

banner = get_ftp_banner(port:ftpPort);
if("Serv-U" >!< banner){
  exit(0);
}

if(egrep(pattern:"Serv-U FTP Server v7\.[0-2]", string:banner)){
  security_message(ftpPort);
  exit(0);
}

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

servPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                               "\Uninstall\Serv-U_is1", item:"DisplayIcon");
if(!servPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:servPath);
file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:servPath);

name   =  kb_smb_name();
login  =  kb_smb_login();
pass   =  kb_smb_password();
domain =  kb_smb_domain();
port   =  kb_smb_transport();

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

r = smb_session_setup(soc:soc, login:login, password:pass, domain:domain,
                      prot:prot);
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

if(egrep(pattern:"^(7\.3(\.0(\.0)?)?)$", string:ftpVer)){
  security_message(ftpPort);
}
