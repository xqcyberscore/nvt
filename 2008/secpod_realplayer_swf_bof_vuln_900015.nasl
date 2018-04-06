##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_realplayer_swf_bof_vuln_900015.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: RealPlayer SWF Frame Handling Buffer Overflow Vulnerability (Windows)
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

tag_impact = "Successful exploitation could allow remote attackers to
        execute arbitrary code on a user's system.
 Impact Level : Application/System.";

tag_solution = "Upgrade to the latest version available,
 http://service.real.com/realplayer/security/07252008_player/en/";

tag_affected = "RealPlayer Version 10, 10.5 and 11 on Windows (All).";

tag_insight = "The flaw exists due to a design error in handling/parsing of frames
        in Shockwave Flash (SWF) files.";


tag_summary = "This Remote host is running with RealPlayer, which is prone to
 buffer overflow vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900015");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(30370);
 script_cve_id("CVE-2007-5400");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("Buffer overflow");
 script_name("RealPlayer SWF Frame Handling Buffer Overflow Vulnerability (Windows)");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/27620/");
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

 realPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
		                "\App Paths\realplay.exe", item:"Path");
 if(!realPath){
	exit(0);
 }

 realExe = realPath + "\realplay.exe";

 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:realExe);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:realExe);

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
        exit(0);
 }

 prot = smb_neg_prot(soc:soc);
 if(!prot){
        exit(0);
 }

 r = smb_session_setup(soc:soc, login:login, password:pass,
                       domain:domain, prot:prot);
 if(!r){
        exit(0);
 }

 uid = session_extract_uid(reply:r);
 if(!uid){
        exit(0);
 }

 r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
 if(!r){
        exit(0);
 }

 tid = tconx_extract_tid(reply:r);
 if(!tid){
        exit(0);
 }

 fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
 if(!fid){
        exit(0);
 }

 fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
 off = fsize - 90000;

 while(fsize != off)
 {
        data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
        data = str_replace(find:raw_string(0), replace:"", string:data);
        version = strstr(data, "ProductVersion");
        if(!version){
                off += 16383;
        }
        else break;
 }

 if(!version){
        exit(0);
 }

 v = "";
 for(i = strlen("ProductVersion"); i < strlen(version); i++)
 {
        if((ord(version[i]) < ord("0") ||
            ord(version[i]) > ord("9")) && version[i] != "."){
                break;
        }
        else
                v += version[i];
 }

 # Grep for RealPlayer versions <= 11 (6.0.14.806, 6.0.14.738-6.0.14.802) and
 # RealPlayer version <= 10 (6.0.12.1040-6.0.12.1663, 6.0.12.1675, 6.0.12.1698,
 # and 6.0.12.1741)
 if(ereg(pattern:"^([0-5]\..*|6\.0\.([0-9]\..*|1?[01]\..*|12\.(10[4-9]?[0-9]?" +
		 "|1[1-5][0-9][0-9]|16[0-5][0-9]|166[0-3]|1675|1698|1741)|" +
		 "14\.(73[89]|7[4-9][0-9]|80[0-2]|806)))$",
 	 string:v)){
        security_message(0);
 }
