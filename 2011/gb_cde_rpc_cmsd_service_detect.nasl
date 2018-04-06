###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cde_rpc_cmsd_service_detect.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Calendar Manager Service rpc.cmsd Service Detection
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_solution = "HEWLETT-PACKARD and Sun Microsystems, Inc have released a
patch to fix this issue, please refer below link for more information.
http://www.securityfocus.com/advisories/1691
http://www.securityfocus.com/advisories/1721

For other distributions please contact your vendor.";

tag_impact = "Successful exploitation could allow attackers to execute
arbitrary code with the privileges of the rpc.cmsd daemon, typically root.
With some configurations rpc.cmsd runs with an effective userid of daemon,
while retaining root privileges.

Impact Level: System";

tag_insight = "The flaw is due to error in the 'rpc.cmsd' service. If this
service is running then disable it as it may become a security issue.";

tag_summary = "This script detects the running 'rpc.cmsd' service on the host.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802163");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-1999-0696", "CVE-1999-0320");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("Calendar Manager Service rpc.cmsd Service Detection");

  script_xref(name : "URL" , value : "http://www.cert.org/advisories/CA-99-08-cmsd.html");
  script_xref(name : "URL" , value : "http://www.iss.net/security_center/reference/vuln/sun-cmsd-bo.htm");
  script_xref(name : "URL" , value : "http://www1.itrc.hp.com/service/cki/docDisplay.do?docId=HPSBUX9908-102");

  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("RPC");
  script_dependencies("secpod_rpc_portmap.nasl");
  script_require_keys("rpc/portmap");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "solution" , value : tag_solution);
  exit(0);
}

include("misc_func.inc");
include("byte_func.inc");

RPC_PROG = 100068;

## Get the rpc port, running rpc.rquotad service
port = get_rpc_port(program: RPC_PROG, protocol: IPPROTO_UDP);
if(port)
{
  security_message(port);
  exit(0);
}

port = get_rpc_port(program: RPC_PROG, protocol: IPPROTO_TCP);
if(port){
  security_message(port);
  exit(0);
}
