##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_f-prot_av_mult_vuln_900018.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: F-PROT Antivirus Multiple Vulnerabilities
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

tag_impact = "Remote attackers can easily crash the engine/service via
        specially crafted files.
 Impact Level : Application.";

tag_solution = "Upgrade to latest F-PROT Antivirus or later.
 http://www.f-prot.com/download/";

tag_affected = "F-Prot Antivirus for Windows prior to 6.0.9.0 on Windows (All).";

tag_insight = "The issues are due to,
        - input validation error while processing the nb_dir field of
          CHM file's header.
        - improper handling of specially crafted UPX-compressed files,
          Microsoft Office files, and ASPack-compressed files.";


tag_summary = "The remote host is installed with F-PROT Antivirus, which is
 prone multiple denial of service vulnerabilities.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900018");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3244");
 script_bugtraq_id(30253, 30258);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Denial of Service");
 script_name("F-PROT Antivirus Multiple Vulnerabilities");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://www.f-prot.com/download/ReleaseNotesWindows.txt");
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

 if(!registry_key_exists(key:"SOFTWARE\FRISK Software\F-PROT Antivirus for Windows")){
	exit(0);
 }

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
 if(key_h)
 {
        entries = registry_enum_key(soc:soc, uid:uid, tid:tid,
                                    pipe:pipe, reply:key_h);
        close(soc);
        foreach entry (entries)
        {
                fprotName = registry_get_sz(item:"DisplayName",
                                             key:key + entry);
                if("F-PROT Antivirus for Windows" >< fprotName)
                {
                        fprotVer = registry_get_sz(item:"DisplayVersion",
                                                    key:key + entry);
                        if(egrep(pattern:"^([0-5]\..*|6\.0\.[0-8](\..*)?)$",
				 string:fprotVer)){
				security_message(0);
                        }
                        exit(0);
                }
        }
 }
