##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_anzio_web_print_obj_bof_vuln_900115.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Anzio Web Print Object ActiveX Control Remote BOF Vulnerability
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

tag_impact = "An attacker can execute arbitrary code causing a stack based
        buffer overflow by tricking a user to visit malicious web page.

 Impact Level : Application";

tag_solution = "Upgrade to Anzio Web Print Object version 3.2.30
 http://www.anzio.com/download-wepo.htm";

tag_affected = "Anzio Web Print Object versions prior to 3.2.30 on Windows (All)";

tag_insight = "The flaw is due to an error while handling an overly long value in 
        mainurl parameter.";

tag_summary = "The host is running Anzio, which is prone to a heap-based buffer
 overflow vulnerability.";



if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900115");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-09-02 07:39:00 +0200 (Tue, 02 Sep 2008)");
 script_bugtraq_id(30545);
 script_cve_id("CVE-2008-3480");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Buffer overflow");
 script_name("Anzio Web Print Object ActiveX Control Remote BOF Vulnerability");

 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31554/");
 script_xref(name : "URL" , value : "http://en.securitylab.ru/poc/extra/358295.php");
 script_xref(name : "URL" , value : "http://www.coresecurity.com/content/anzio-web-print-object-buffer-overflow");
 exit(0);
}


 include("smb_nt.inc");
 include("secpod_smb_func.inc");

 if (!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 anzioPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion"
				+ "\App Paths\pwui.exe", item:"Path");
 if(!anzioPath){
        exit(0);
 }

 share = ereg_replace(pattern:"([A-Z]):.*",replace:"\1$",string:anzioPath);
 file = ereg_replace(pattern:"[A-Z]:(.*)",replace:"\1",string:anzioPath + "\pwui.exe");

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

 anzioVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"File Version");
 close(soc);

 if(!anzioVer){
        exit(0);
 }

 if(egrep(pattern:"^([0-2]\..*|3\.([01](\..*)?|2(\.[0-2]?[0-9])?\.0))$",
	  string:anzioVer)){
 	security_message(0);
 }
