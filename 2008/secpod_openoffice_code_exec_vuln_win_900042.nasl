##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openoffice_code_exec_vuln_win_900042.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability (Windows)
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

tag_impact = "Attackers can cause an out of bounds array access by tricking a
        user into opening a malicious document, also allow execution of arbitrary
        code.
 Impact Level : System";

tag_solution = "Upgrade to OpenOffice.org Version 3.2.0 or later,
 For updates refer to http://download.openoffice.org/index.html";

tag_affected = "OpenOffice.org 2.4.1 and prior on Windows.";

tag_insight = "The issue is due to a numeric truncation error within the rtl_allocateMemory()
        method in alloc_global.c file.";


tag_summary = "This host has OpenOffice.Org installed, which is prone to remote
 code execution vulnerability.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900042");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
 script_bugtraq_id(30866);
 script_cve_id("CVE-2008-3282");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("General");
 script_name("OpenOffice rtl_allocateMemory() Remote Code Execution Vulnerability (Windows)");

 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31640/");
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2449");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 name   =  kb_smb_name();
 login  =  kb_smb_login();
 pass   =  kb_smb_password();
 domain =  kb_smb_domain();
 port   =  kb_smb_transport();
 
 if(!port) port = 139;
 
 if(!get_port_state(port))exit(0);
 
 soc = open_sock_tcp(port);
 if(!soc){
        exit(0);
 }
 
 r = smb_session_request(soc:soc, remote:name);
 if(!r)
 {
        close(soc);
        exit(0);
 }
 
 prot = smb_neg_prot(soc:soc);
 if(!prot)
 {
        close(soc);
        exit(0);
 }
 
 r = smb_session_setup(soc:soc, login:login, password:pass,
                       domain:domain, prot:prot);
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
 if(!tid)
 {
        close(soc);
        exit(0);
 }

 r = smbntcreatex(soc:soc, uid:uid, tid:tid, name:"\winreg");
 if(!r)
 {
        close(soc);
        exit(0);
 }

 pipe = smbntcreatex_extract_pipe(reply:r);
 if(!pipe)
 {
        close(soc);
        exit(0);
 }

 r = pipe_accessible_registry(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!r)
 {
        close(soc);
        exit(0);
 }

 handle = registry_open_hklm(soc:soc, uid:uid, tid:tid, pipe:pipe);
 if(!handle)
 {
        close(soc);
        exit(0);
 }
 
 key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
 key_h = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe,
                          key:key, reply:handle);
 if(!key_h)
 {
        close(soc);
        exit(0);
 }

 entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);
 close(soc);

 foreach item (entries)
 {
        if("OpenOffice.org" >< registry_get_sz(key:key + item, item:"DisplayName"))
        {
		# Grep <= 2.4.9310 (ie., 2.4.1)
 		if((egrep(pattern:"^([01]\..*|2\.([0-3](\..*)?|4(\.([0-8]?[0-9]?" +
				  "[0-9]?[0-9]|9[0-2][0-9][0-9]|930[0-9]|9310))?))$",
                    	  string:registry_get_sz(key:key + item,
                    	  item:"DisplayVersion")))){
			security_message(0);
		}
		exit(0);
        }
 }
