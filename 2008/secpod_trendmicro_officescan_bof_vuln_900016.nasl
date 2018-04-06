##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_trendmicro_officescan_bof_vuln_900016.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Trend Micro OfficeScan ObjRemoveCtrl ActiveX Control BOF Vulnerability
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
        execute arbitrary code.
 Impact Level : Application.";

tag_solution = "Upgrade to OfficeScan 10 or later,
 For updates refer to http://uk.trendmicro.com/uk/downloads/enterprise/index.html";

tag_affected = "OfficeScan 7.3 build 1343 (Patch 4) and prior on Windows (All).
        Trend Micro Worry-Free Business Security (WFBS) version 5.0
        Trend Micro Client Server Messaging Security (CSM) versions 3.5 and 3.6

 Quick Fix: Set killbits for the following clsid's
             {5EFE8CB1-D095-11D1-88FC-0080C859833B}
             To set kill-bit refer, http://support.microsoft.com/kb/240797";

tag_insight = "The flaws are due to an error in objRemoveCtrl control, which is used to display 
        certain properties (eg., Server, ServerIniFile etc..) and their values when it is embedded
        in a web page. These property values can be overflowed to cause stack based overflow.";


tag_summary = "This Remote host is installed with Trend Micro OfficeScan, which
 is prone to ActiveX control buffer overflow vulnerability.";

if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900016");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3364");
 script_bugtraq_id(30407);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Buffer overflow");
 script_name("Trend Micro OfficeScan ObjRemoveCtrl ActiveX Control BOF Vulnerability");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/6152");
 script_xref(name : "URL" , value : "http://archives.neohapsis.com/archives/fulldisclosure/2008-07/0509.html");
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

 key = "SOFTWARE\TrendMicro\OfficeScan\service\Information";
 scanVer = registry_get_sz(key:key, item:"Server_Version");

 if(!scanVer){
	exit(0);
 }

 if(egrep(pattern:"^([0-6]\..*|7\.[0-2])$", string:scanVer))
 {
	security_message(0);
	exit(0);
 }

 if("7.3" >!< scanVer){
	exit(0);
 }

 scanPath = registry_get_sz(key:key, item:"Local_Path");
 if(!scanPath){
	exit(0);
 }

 scanPath += "pccnt\PccNTRes.dll";

 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:scanPath);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:scanPath);

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

 r = smb_tconx(soc:soc, name:name, uid:uid, share:share);
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

 fid = OpenAndX(socket:soc, uid:uid, tid:tid, file:file);
 if(!fid)
 {
	close(soc);
        exit(0);
 }

 fsize = smb_get_file_size(socket:soc, uid:uid, tid:tid, fid:fid);
 off = fsize - 90000;

 while(fsize != off)
 {
        data = ReadAndX(socket:soc, uid:uid, tid:tid, fid:fid, count:16384, off:off);
        data = str_replace(find:raw_string(0), replace:"", string:data);
        version = strstr(data, "SpecialBuild");
        if(!version){
                off += 16383;
        }
        else break;
 }

 close(soc);
 if(!version){
        exit(0);
 }

 v = "";
 for(i = strlen("SpecialBuild"); i < strlen(version); i++)
 {
        if((ord(version[i]) < ord("0") ||
            ord(version[i]) > ord("9")) && version[i] != "."){
                break;
        }
        else
                v += version[i];
 }

 # Grep for OfficeScan 7.3 build 1343 (Patch 4) and prior.
 if(egrep(pattern:"^([0-9]?[0-9]?[0-9]|1[0-2][0-9][0-9]|13([0-3][0-9]|" +
	  	  "4[0-3]))$", string:v))
 {
	clsid = "{5EFE8CB1-D095-11D1-88FC-0080C859833B}";
        clsidKey = "SOFTWARE\Classes\CLSID\"+ clsid;
        if(registry_key_exists(key:clsidKey))
        {
                # Check kill bit is set for ActiveX control
                activeKey = "SOFTWARE\Microsoft\Internet Explorer\" +
                            "ActiveX Compatibility\" + clsid;
                killBit = registry_get_dword(key:activeKey,
                                             item:"Compatibility Flags");
                if(!killBit){
                        security_message(0);
                }
        }
 }
