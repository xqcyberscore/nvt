##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_canon_printer_mult_vuln.nasl 30300 2013-06-19 12:00:59Z June$
#
# Canon Printer Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow remote attackers to cause
the denial of service and obtain the sensitive information.

Impact Level: Application";

tag_affected = "Canon Printers";

tag_insight = "- Printers do not require a password for the administrative
interfaces by default. Unauthorized users on the network may configure the printer.
- Administrative interface on these printers allow a user to enter a
  WEP/WPA/WPA2 pre-shared key. Once a key is entered, when a user browses
  the configuration page again, they can view the current password in
  clear-text.
- Administrative interface on the devices, Using specially crafted HTTP
  requests, it is possible to cause the device to no longer respond.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Canon Printer and is prone to multiple
vulnerabilities.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.803718";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 6093 $");
  script_cve_id("CVE-2013-4613", "CVE-2013-4614", "CVE-2013-4615");
  script_bugtraq_id(60612, 60601, 60598);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2017-05-10 11:03:18 +0200 (Wed, 10 May 2017) $");
  script_tag(name:"creation_date", value:"2013-06-19 12:00:59 +0530 (Wed, 19 Jun 2013)");
  script_name("Canon Printer Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://packetstormsecurity.com/files/122073/");
  script_xref(name : "URL" , value : "http://www.mattandreko.com/2013/06/canon-y-u-no-security.html");
  script_xref(name : "URL" , value : "http://exploitsdownload.com/exploit/na/canon-printer-dos-secret-disclosure");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (c) 2013 Greenbone Networks");
  script_family("General");
  script_dependencies("gb_canon_printers_detect.nasl");
  script_mandatory_keys("canon_printer/installed", "canon_printer_model",
                        "canon_printer/port");
  script_require_ports("Services/www", 80);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = "";
model = "";

## get the printer  port
port = get_kb_item("canon_printer/port");
if(!port){
  exit(0);
}

## get the model name
model = get_kb_item("canon_printer_model");
if(!model){
  exit(0);
}

## Confirm the exploit by reading  content of Nologin.asp
if(http_vuln_check(port:port, url:"/English/pages_MacUS/wls_set_content.html",
   pattern:">Authentication Type:", extra_check:make_list(">Passphrase:",
                                                          ">Password")))
{
  security_message(port:port);
  exit(0);
}
