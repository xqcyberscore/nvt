###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exim_4_72.nasl 8495 2018-01-23 07:57:49Z teissa $
#
# Exim < 4.72 RC2 Multiple Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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
###############################################################################

tag_summary = "According to the version from its Banner, the remote Exim is prone to 
multiple vulnerabilities.

1.
Exim creates temporary files in an insecure manner.

An attacker with local access could potentially exploit this issue to
perform symbolic-link attacks.

Successfully mounting a symlink attack may allow the attacker to
delete or corrupt sensitive files, which may result in a denial of
service. Other attacks may also be possible.

2.
Exim is prone to a local privilege-escalation vulnerability.

Local attackers can exploit this issue to gain elevated privileges on
affected computers.

Versions prior to Exim 4.72 RC2 are vulnerable.";

tag_solution = "Updates are available; please see the references for more information.";

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.100663");
 script_version("$Revision: 8495 $");
 script_tag(name:"last_modification", value:"$Date: 2018-01-23 08:57:49 +0100 (Tue, 23 Jan 2018) $");
 script_tag(name:"creation_date", value:"2010-06-03 13:39:07 +0200 (Thu, 03 Jun 2010)");
 script_bugtraq_id(40454,40451);
 script_cve_id("CVE-2010-2024","CVE-2010-2023");

 script_name("Exim < 4.72 RC2 Multiple Vulnerabilities");


 script_tag(name:"cvss_base", value:"4.4");
 script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("SMTP problems");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
 script_require_ports("Services/smtp", 25);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40454");
 script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/40451");
 script_xref(name : "URL" , value : "http://lists.exim.org/lurker/message/20100524.175925.9a69f755.en.html");
 script_xref(name : "URL" , value : "http://bugs.exim.org/show_bug.cgi?id=989");
 script_xref(name : "URL" , value : "http://vcs.exim.org/viewvc/exim/exim-doc/doc-txt/ChangeLog?view=markup&pathrev=exim-4_72_RC2");
 script_xref(name : "URL" , value : "http://www.exim.org/");
 exit(0);
}

include("smtp_func.inc");
include("version_func.inc");

port = get_kb_item("Services/smtp");
if(!port) port = 25;

if(get_kb_item('SMTP/'+port+'/broken'))exit(0);
if(!get_port_state(port))exit(0);

banner = get_smtp_banner(port:port);
if(!banner || "exim" >!< tolower(banner))exit(0);

version = eregmatch(pattern:"220.*exim ([0-9.]+)", string: tolower(banner));
if(isnull(version[1]))exit(0);

if(version_is_less(version:version[1], test_version:"4.72")) {
 
  security_message(port:port);
  exit(0);

}  

exit(0);
