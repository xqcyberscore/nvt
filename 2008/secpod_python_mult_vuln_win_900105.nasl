##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_python_mult_vuln_win_900105.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Python Multiple Vulnerabilities (Windows)
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

tag_impact = "Successful exploitation could potentially causes attackers to
        execute arbitrary code or create a denial of service condition.
 Impact Level : Application";

tag_solution = "Fix is available in the SVN repository,
 http://svn.python.org";

tag_affected = "Python 2.5.2 and prior on Linux (All).";

tag_insight = "The flaws exist due to integer overflow in,
        - hashlib module, which can lead to an unreliable cryptographic digest
          results.
        - the processing of unicode strings.
        - the PyOS_vsnprintf() function on architectures that do not have a
          vsnprintf() function.
        - the PyOS_vsnprintf() function when passing zero-length strings can
          lead to memory corruption.";


tag_summary = "The host is installed with Python, which is prone to multiple
 vulnerabilities.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900105");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(30491);
 script_cve_id("CVE-2008-2315", "CVE-2008-2316", "CVE-2008-3142", 
	       "CVE-2008-3143","CVE-2008-3144");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.5");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("Buffer overflow");
 script_name("Python Multiple Vulnerabilities (Windows)");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_xref(name : "URL" , value : "http://bugs.python.org/issue2588");
 script_xref(name : "URL" , value : "http://bugs.python.org/issue2589");
 script_xref(name : "URL" , value : "http://bugs.python.org/issue2620");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}


 include("smb_nt.inc");

 if(!(get_kb_item("SMB/WindowsVersion"))){
        exit(0);
 }

 name = kb_smb_name();
 login = kb_smb_login();
 domain = kb_smb_domain();
 pass = kb_smb_password();
 port = kb_smb_transport();

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
 pyKey = registry_get_key(soc:soc, uid:uid, tid:tid, pipe:pipe, key:key, reply:handle);
 if(!pyKey)
 {
	close(soc);
        exit(0);
 }

 entries = registry_enum_key(soc:soc, uid:uid, tid:tid, pipe:pipe, reply:pyKey);
 close(soc);

 foreach entry (entries)
 {
        pyName = registry_get_sz(key:key + entry, item:"DisplayName");
        if("Python" >< pyName)
        {
          	if(egrep(pattern:"Python ([01]\..*|2\.([0-4]\..*|5\.[0-2]))$",
			 string:pyName)){
                	security_message(0);
		}
                exit(0);
        }
 }
