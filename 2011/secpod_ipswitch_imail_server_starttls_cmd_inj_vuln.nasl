###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ipswitch_imail_server_starttls_cmd_inj_vuln.nasl 7029 2017-08-31 11:51:40Z teissa $
#
# Ipswitch IMail Server STARTTLS Plaintext Command Injection Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

tag_impact = "Successful exploitation will allow attacker to execute arbitrary
commands in the context of the user running the application.

Impact Level: Application";

tag_affected = "Ipswitch IMail versions 11.03 and Prior.";

tag_insight = "This flaw is caused by an error within the 'STARTTLS'
implementation where the switch from plaintext to TLS is implemented below the
application's I/O buffering layer, which could allow attackers to inject
commands during the  plaintext phase of the protocol via man-in-the-middle
attacks.";

tag_solution = "Upgrade to Ipswitch IMail version 11.5 or later.
For updates refer to http://www.imailserver.com/";

tag_summary = "The host is running Ipswitch IMail Server and is prone to
plaintext command injection vulnerability.";

if(description)
{
  script_id(901195);
  script_version("$Revision: 7029 $");
  script_tag(name:"last_modification", value:"$Date: 2017-08-31 13:51:40 +0200 (Thu, 31 Aug 2017) $");
  script_tag(name:"creation_date", value:"2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)");
  script_cve_id("CVE-2011-1430");
  script_bugtraq_id(46767);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("Ipswitch IMail Server STARTTLS Plaintext Command Injection Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43676");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2011/060");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "smtpserver_detect.nasl");
  script_require_ports("Services/smtp","Services/pop3","Services/imap",25, 110, 143);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("smtp_func.inc");
include("pop3_func.inc");
include("imap_func.inc");
include("version_func.inc");

## Check Vulnerable IMail Server Versions.
function check_vuln(banner,port)
{
  version = eregmatch(pattern: "IMail ([0-9.]+)", string: banner);
  if(!isnull(version[1]))
  {
    if(version_is_less_equal(version: version[1], test_version:"11.03"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}

## Get SMTP Port
port = get_kb_item("Services/smtp");
if(!port) {
  port = 25;
}

## Get SMTP Banner
if(banner = get_smtp_banner(port:port))
{
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }
}

## Check POP3 Port
port = get_kb_item("Services/pop3");
if(!port) {
  port = 110;
}

## Get POP3 Baner
if(banner = get_pop3_banner(port:port))
{
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }
}

## Check IMAP Port
port = get_kb_item("Services/imap");
if(!port) {
  port = 143;
}

## Get IMAP Banner
if(banner = get_imap_banner(port:port))
{
  if("IMail" >< banner) {
    check_vuln(banner:banner,port:port);
  }
}
