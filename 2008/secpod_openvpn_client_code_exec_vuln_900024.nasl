##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_openvpn_client_code_exec_vuln_900024.nasl 7823 2017-11-20 08:54:04Z cfischer $
# Description: OpenVPN Client Remote Code Execution Vulnerability
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

tag_impact = "Remote attackers could execute arbitrary code on the Client.

        Successful exploitation requires,
        - the client to agree to allow the server to push configuration
          directives to it by including pull or the macro client in its
          configuration file.
        - the client successfully authenticates the server.
        - the server is malicious and has been compromised under the control
          of the attacker.
 Impact Level : Application/System";

tag_solution = "Upgrade to higher version of Non-Windows OpenVPN client OpenVPN 2.1-rc9
 http://openvpn.net/index.php/downloads.html";

tag_affected = "Non-Windows OpenVPN client OpenVPN 2.1-beta14 to OpenVPN 2.1-rc8";


tag_summary = "The host is running OpenVPN Client, which is prone to remote code
 execution vulnerability.";

tag_insight = "Application fails to properly validate the specially crafted input
        passed to lladdr/iproute configuration directives.";

if(description)
{
 script_id(900024);
 script_version("$Revision: 7823 $");
 script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_bugtraq_id(30532);
 script_cve_id("CVE-2008-3459");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"7.6");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("General");
 script_name("OpenVPN Client Remote Code Execution Vulnerability");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success");
 script_exclude_keys("ssh/no_linux_shell");

 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2316");
 script_xref(name : "URL" , value : "http://openvpn.net/index.php/documentation/change-log/changelog-21.html");
 exit(0);
}

include("ssh_func.inc");
 
foreach item (get_kb_list("ssh/login/rpms"))
{
        if("openvpn~" >< item)
        {
		# Grep for openvpn 2.1-beta14 to 2.1-rc8
                if(egrep(pattern:"^openvpn~2.1~.*(beta14|rc[0-8])($|[^0-9])",
			 string:item)){
                        security_message(0);
                }
                exit(0);
        }
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
        exit(0);
 }
 
 vpnVer = ssh_cmd(socket:sock, cmd:"openvpn --version");
 ssh_close_connection();
 
 if(!vpnVer){
        exit(0);
 }

 # Grep for openvpn 2.1-beta14 to 2.1-rc8
 if(egrep(pattern:"OpenVPN 2.1_(beta14|rc[0-8])($|[^.0-9])", string:vpnVer)){
        security_message(0);
 }
