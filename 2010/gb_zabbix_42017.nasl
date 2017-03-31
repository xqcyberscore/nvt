###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zabbix_42017.nasl 5388 2017-02-21 15:13:30Z teissa $
#
# ZABBIX 'formatQuery()' Cross Site Scripting Vulnerability
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

tag_summary = "ZABBIX is prone to a cross-site scripting vulnerability
because it fails to properly sanitize user-supplied input.

An attacker may leverage this issue to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site. This may allow the attacker to steal cookie-based authentication
credentials and to launch other attacks.

ZABBIX version 1.8.2 is vulnerable; other versions may also be
affected.";

tag_solution = "Updates are available. Please see the reference for more details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100729";
CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5388 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-21 16:13:30 +0100 (Tue, 21 Feb 2017) $");
 script_tag(name:"creation_date", value:"2010-08-02 14:28:14 +0200 (Mon, 02 Aug 2010)");
 script_tag(name:"cvss_base", value:"4.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2010-2790");
 script_bugtraq_id(42017);

 script_name("ZABBIX 'formatQuery()' Cross Site Scripting Vulnerability");

 script_xref(name : "URL" , value : "https://www.securityfocus.com/bid/42017");
 script_xref(name : "URL" , value : "http://www.zabbix.org");
 script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-2326");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_GATHER_INFO);
 script_family("Web application abuses");
 script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
 script_dependencies("zabbix_detect.nasl","zabbix_web_detect.nasl");
 script_require_ports("Services/www","Services/zabbix_server", 80,10051);
 script_mandatory_keys("Zabbix/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
if(!get_port_state(port))exit(0);

if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

if(!isnull(vers) && vers >!< "unknown") {

  if(version_is_equal(version: vers, test_version: "1.8.2")) {
    security_message(port:port);
    exit(0);
  }

}

exit(0);

