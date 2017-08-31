###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_symantec_messaging_gateway_snmp_detect.nasl 6490 2017-06-30 05:39:55Z ckuersteiner $
#
# Symantec Messaging Gateway Detection (SNMP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

if (description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.105718");
 script_tag(name:"cvss_base", value:"0.0");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version ("$Revision: 6490 $");
 script_tag(name:"last_modification", value:"$Date: 2017-06-30 07:39:55 +0200 (Fri, 30 Jun 2017) $");
 script_tag(name:"creation_date", value:"2016-05-17 12:13:39 +0200 (Tue, 17 May 2016)");
 script_name("Symantec Messaging Gateway Detection (SNMP)");

 script_tag(name: "summary" , value: "This script performs SNMP based detection of Symantec Messaging Gateway");

 script_tag(name:"qod_type", value:"remote_banner");

 script_category(ACT_GATHER_INFO);
 script_family("Service detection");
 script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
 script_dependencies("gb_snmp_get_installed_sw.nasl");
 script_require_udp_ports("Services/udp/snmp", 161);
 script_mandatory_keys("SNMP/installed_software");
 exit(0);
}

include("snmp_func.inc");

if (!release = snmp_get_sw_oid(pattern: "sms-appliance-release"))
  exit(0);

replace_kb_item(name: "smg/installed", value: TRUE);

vers = eregmatch(pattern: 'sms-appliance-release-([0-9+][^ $\r\n"]+)', string: release[1]);
if (!isnull(vers[1])) {
  version = vers[1];
  if ("-" >< version) {
    v = split(version, sep: "-", keep: FALSE);
    version = v[0];
    patch = v[1];
  }

  if (p = snmp_get_sw_oid(pattern: "sms-appliance-patch")) {
    pa = eregmatch(pattern: "sms-appliance-patch-" + version + "-([0-9]+)", string: p[1]);
    if (!isnull(pa[1]))
      patch = pa[1];
  }

  if (version)
    set_kb_item(name: "symantec_messaging_gateway/version/snmp", value: version);

  if (patch)
    set_kb_item(name: "symantec_messaging_gateway/patch/snmp", value: patch);
}

exit(0);

