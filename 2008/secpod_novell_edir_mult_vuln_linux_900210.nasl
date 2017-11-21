##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_edir_mult_vuln_linux_900210.nasl 7823 2017-11-20 08:54:04Z cfischer $
# Description: Novell eDirectory Multiple Vulnerabilities (Linux)
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

tag_impact = "Successful Remote exploitation will allow execution of
        arbitrary code, heap-based buffer overflow, Cross Site Scripting 
        attacks, or cause memory corruption.
 Impact Level : System";

tag_solution = "Apply 8.8 Service Pack 3.
 http://download.novell.com/Download?buildid=RH_B5b3M6EQ~";

tag_affected = "Novell eDirectory 8.8 SP2 and prior versions on Linux (All).";

tag_insight = "Multiple flaw are due to,
        - errors in HTTP Protocol Stack that can be exploited to cause heap
          based buffer overflow via a specially crafted language/content-length
          headers.
        - input passed via unspecified parameters to the HTTP Protocol Stack is
          not properly sanitzed before being returned to the user.
        - Multiple unknown error exist in LDAP and NDS services.";


tag_summary = "This host is running Novell eDirectory, which is prone to XSS,
 Denial of Service, and Remote Code Execution Vulnerabilities.";


if(description)
{
 script_id(900210);
 script_version("$Revision: 7823 $");
 script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
 script_tag(name:"creation_date", value:"2008-09-02 16:25:07 +0200 (Tue, 02 Sep 2008)");
 script_cve_id("CVE-2008-5091","CVE-2008-5092","CVE-2008-5093","CVE-2008-5094","CVE-2008-5095");
 script_bugtraq_id(30947);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"10.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("Buffer overflow");
 script_name("Novell eDirectory Multiple Vulnerabilities (Linux)");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success");
 script_exclude_keys("ssh/no_linux_shell");

 script_xref(name : "URL" , value : "http://secunia.com/advisories/31684");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020788.html");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020787.html");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020786.html");
 script_xref(name : "URL" , value : "http://securitytracker.com/alerts/2008/Aug/1020785.html");
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 exit(0);
}

include("ssh_func.inc");

 sock = ssh_login_or_reuse_connection();
 if(!sock){
 	exit(0);
 }

 output = ssh_cmd(socket:sock, cmd:"ndsd --version", timeout:120);
 if("Novell eDirectory" >!< output)
 {
        output = ssh_cmd(socket:sock, timeout:120,
			 cmd:"/opt/novell/eDirectory/sbin/ndsd --version");
 }

 ssh_close_connection();

 if("Novell eDirectory" >!< output){
        exit(0);
 }

 if(!(egrep(pattern:"^Novell eDirectory ([0-7]\..*|8\.[0-7]( .*)?|8\.8( SP[0-2])?)[^.0-9]",
            string:output))){
        exit(0);
 }

 rpmList = get_kb_list("ssh/login/rpms");
 foreach rpm (rpmList)
 {
        if((egrep(pattern:"^novell-AUDTedirinst~(9\.|8\.9\.|8.8.3|[1-9][0-9]+\.)",
                   string:rpm))){
                exit(0);
        }
 }
 security_message(port:0);
