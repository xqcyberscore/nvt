##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_pidgin_ssl_sec_bypass_vuln_lin_900022.nasl 7823 2017-11-20 08:54:04Z cfischer $
# Description: Pidgin NSS plugin SSL Certificate Validation Security Bypass Vulnerability (Linux)
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

tag_impact = "Man-in-the-middle attacks or identity impersonation attacks are possible.
 Impact Level : Network.";

tag_solution = "Apply the patch,
 http://developer.pidgin.im/attachment/ticket/6500/nss-cert-verify.patc h";


tag_summary = "The host is running Pidgin, which is prone to Security Bypass
 Vulnerability";

tag_affected = "Pidgin Version 2.4.3 and prior on Linux.";
tag_insight = "The application fails to properly validate SSL (Secure Sockets Layer) 
        certificate from a server.";


if(description)
{
 script_id(900022);
 script_version("$Revision: 7823 $");
 script_tag(name:"last_modification", value:"$Date: 2017-11-20 09:54:04 +0100 (Mon, 20 Nov 2017) $");
 script_tag(name:"creation_date", value:"2008-08-22 10:29:01 +0200 (Fri, 22 Aug 2008)");
 script_cve_id("CVE-2008-3532");
 script_bugtraq_id(30553);
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"6.8");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
 script_family("General");
 script_name("Pidgin NSS plugin SSL Certificate Validation Security Bypass Vulnerability (Linux)");
 script_dependencies("gather-package-list.nasl");
 script_mandatory_keys("login/SSH/success");
 script_exclude_keys("ssh/no_linux_shell");

 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://developer.pidgin.im/ticket/6500 ");
 exit(0);
}

include("ssh_func.inc");

 foreach item (get_kb_list("ssh/login/rpms"))
 {
	if("pidgin~" >< item)
	{
		if(egrep(pattern:"^pidgin~([01]\..*|2\.([0-3](\..*)?|" +
				 "4(\.[0-3])?))($|[^.0-9])", string:item))
		{
                	security_message(0);
			exit(0);
		}
 	}
 }

 sock = ssh_login_or_reuse_connection();
 if(!sock){
	exit(0);
 }

 pidginVer = ssh_cmd(socket:sock, cmd:"pidgin --version");
 ssh_close_connection();

 if(!pidginVer){
	exit(0);
 }

 if(egrep(pattern:"Pidgin ([01]\..*|2\.([0-3](\..*)?|4(\.[0-3])?))($|[^.0-9])",
	  string:pidginVer)){
 	security_message(0);
 }
