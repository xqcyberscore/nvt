##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ms08-055_900046.nasl 5370 2017-02-20 15:24:26Z cfi $
# Description: Microsoft Office Remote Code Execution Vulnerabilities (955047)
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

tag_impact = "Remote attackers could be able to execute arbitrary code
        via a specially crafted OneNote URI referencing a specially crafted
        One Note file.
 Impact Level : Application";

tag_solution = "Run Windows Update and update the listed hotfixes or download and
 update mentioned hotfixes in the advisory from the below link.
 http://www.microsoft.com/technet/security/bulletin/ms08-055.mspx";

tag_affected = "Microsoft Office XP/2003/2007 on Windows (All).";

tag_insight = "The issue is due to an error in the parsing of a URI using
        the onenote:// protocol handler.";


tag_summary = "This host is missing critical security update according to
 Microsoft Bulletin MS08-055.";


if(description)
{
 script_id(900046);
 script_version("$Revision: 5370 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-20 16:24:26 +0100 (Mon, 20 Feb 2017) $");
 script_tag(name:"creation_date", value:"2008-09-10 17:51:23 +0200 (Wed, 10 Sep 2008)");
 script_bugtraq_id(31067);
 script_cve_id("CVE-2008-3007");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
 script_family("Windows : Microsoft Bulletins");
 script_name("Microsoft Office Remote Code Execution Vulnerabilities (955047)");
 script_dependencies("secpod_reg_enum.nasl", "secpod_ms_office_detection_900025.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.microsoft.com/technet/security/bulletin/ms08-055.mspx");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_tag(name:"qod_type", value:"registry");
 script_tag(name:"solution_type", value:"VendorFix");
 exit(0);
}


 include("smb_nt.inc");
 include("secpod_reg.inc");
 include("secpod_smb_func.inc");

 if(hotfix_check_sp(xp:4, win2k:5, win2003:3) <= 0){
         exit(0);
 }


 prgmDir = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                           item:"ProgramFilesDir");
 if(!prgmDir){
	exit(0);
 }

 function get_version(dllPath)
 {
        share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
        file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

        name    =  kb_smb_name();
        login   =  kb_smb_login();
        pass    =  kb_smb_password();
        domain  =  kb_smb_domain();
        port    =  kb_smb_transport();

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

        v = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod", offset:9000000);
        close(soc);
        return v;
 } 

 offVer = get_kb_item("MS/Office/Ver");
 if(!offVer){
	exit(0);
 }

 if(offVer =~ "^10\.")
 {
	dllPath = prgmDir + "\Common Files\Microsoft Shared\Office10\MSO.DLL";

	vers = get_version(dllPath);
        if(vers == NULL){
                exit(0);
        }

	# Grep for version < 10.0.6845
	if(egrep(pattern:"^10\.0\.([0-5]?[0-9]?[0-9]?[0-9]|6([0-7][0-9][0-9]" +
			 "|8([0-3][0-9]|4[0-4])))$", string:vers)){
                security_message(0);
	}
 	exit(0);
 }

 if(offVer =~ "^11\.")
 {
        dllPath = prgmDir + "\Common Files\Microsoft Shared\Office11\MSO.DLL";

        vers = get_version(dllPath);
        if(vers == NULL){
                exit(0);
        }

	# Grep for version < 11.0.8221
	if(egrep(pattern:"^11\.0\.([0-7]?[0-9]?[0-9]?[0-9]|8([01][0-9][0-9]" +
			 "|2[01][0-9]|220))$", string:vers)){
		security_message(0);
	}
        exit(0);
 }

 if(offVer =~ "^12\.")
 {
        dllPath = prgmDir + "\Common Files\Microsoft Shared\Office12\MSO.DLL";

        vers = get_version(dllPath);
        if(vers == NULL){
                exit(0);
        }

	# Grep for version < 12.0.6320.5000
	if(egrep(pattern:"^12\.0\.([0-5].*|62.*|63[01][0-9].*|6320\.[0-4]?" +
			 "[0-9]?[0-9]?[0-9])$", string:vers)){
		security_message(0);
	}
 }
