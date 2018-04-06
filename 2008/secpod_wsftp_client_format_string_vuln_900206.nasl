##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_wsftp_client_format_string_vuln_900206.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Ipswitch WS FTP Client Format String Vulnerability 
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

tag_impact = "Successful exploitation will allow execution of arbitrary code
        on the vulnerable system or cause the application to crash by tricking
        a user into connecting to a malicious ftp server.
 Impact Level : Application";

tag_solution = "Upgrade to Ipswitch WS FTP Home/Professional version 12 or later,
 For updates refer to http://www.ipswitchft.com/products/";

tag_affected = "Ipswitch WS FTP Home/Professional 2007 and prior versions.";

tag_insight = "Issue is due to a format string error when processing responses
        of the FTP server.";


tag_summary = "This host is running WS FTP Client, which is prone to Format String
 Vulnerability.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900206");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-27 11:53:45 +0200 (Wed, 27 Aug 2008)");
 script_bugtraq_id(30720);
 script_cve_id("CVE-2008-3734");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("Denial of Service");
 script_name("Ipswitch WS FTP Client Format String Vulnerability");

 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://secunia.com/advisories/31504/");
 script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/44512");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}


 include("smb_nt.inc");
 include("secpod_smb_func.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 wsFtpDir = registry_get_sz(key:"SOFTWARE\Ipswitch\WS_FTP",
                            item:"Dir");
 if(!wsFtpDir)
 {
        wsFtpDir = registry_get_sz(key:"SOFTWARE\Ipswitch\WS_FTP Home",
                                   item:"Dir");
        if(!wsFtpDir){
                exit(0);
        }
        # Set Flag for Home edition.
        wsFtpHome = TRUE;
 }

 share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:wsFtpDir);
 file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
		      string:wsFtpDir + "\wsftpgui.exe");

 name    =  kb_smb_name();
 login   =  kb_smb_login();
 pass    =  kb_smb_password();
 domain  =  kb_smb_domain();
 port    =  kb_smb_transport();

 if(!port){
	port = 139;
 }

 if(!get_port_state(port)){
	exit(0);
 }

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

 fileVer = GetVersion(socket:soc, uid:uid, tid:tid, fid:fid, verstr:"prod");
 close(soc);

 if(!fileVer){
	exit(0);
 }

 if(wsFtpHome)
 {
        # Grep Home Edition Version <= 2007.0.0.2
        if(egrep(pattern:"^([01][0-9][0-9][0-9]\..*|200[0-6]\..*|" + 
                         "2007\.0\.0\.[0-2])$", string:fileVer)){
                security_message(0);
        }
 }
 else
 {
        # Grep Professional Edition Vesion <= 2007.1.0.0
        if(egrep(pattern:"^([01][0-9][0-9][0-9]\..*|200[0-6]\..*|" + 
                         "2007\.[01]\.0\.0)$", string:fileVer)){
                security_message(0);
        }
 }
