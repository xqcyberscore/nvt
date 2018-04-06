##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_flashget_ftp_pwd_bof_vuln_900203.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: FlashGet FTP PWD Response Remote Buffer Overflow Vulnerability.
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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

tag_impact = "Successful exploitation will allow execution of arbitrary
        code by tricking a user into connecting to a malicious ftp server.
 Impact Level : Application";

tag_solution = "Upgrade to FlashGet version 3.3 or later
 For updates refer to http://www.flashget.com/index_en.htm";

tag_affected = "FlashGet 1.9 (1.9.6.1073) and prior versions on Windows (All).";

tag_insight = "Error exist when handling overly long FTP PWD responses.";


tag_summary = "This host is running FlashGet, which is prone to Remote Buffer
 Overflow Vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900203");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-4321");
 script_bugtraq_id(30685);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Denial of Service");
 script_name("FlashGet FTP PWD Response Remote Buffer Overflow Vulnerability");

 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2381");
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
 
 enumKeys = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:key_h);
 foreach entry (enumKeys)
 {
	# 1.8.x or older
 	if("FlashGet(Jetcar)" >< entry || "FlashGet(JetCar)" >< entry)
	{
		security_message(0);
 		exit(0);
	}

 	if("FlashGet" >< entry)
	{
		flashVer = registry_get_sz(item:"DisplayVersion", key:key + entry);
 		if(flashVer)
		{
			# Grep for <= 1.9.6.1073 (1.9 series)
			if(egrep(pattern:"^(1\.9|1\.9\.[0-5](\..*)?|1\.9\.6(\." + 
					 "(0?[0-9]?[0-9]?[0-9]|10[0-6][0-9]" + 
					 "|107[0-3]))?)$",
		                 string:flashVer)){
        			security_message(0);
		 	}
		}
 		exit(0);
	}
 }
