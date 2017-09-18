###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pulse_connect_secure_snmp_detect.nasl 7143 2017-09-15 11:37:02Z santu $
#
# Pulse Connect Secure Detection (SNMP)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811737");
  script_version("$Revision: 7143 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-15 13:37:02 +0200 (Fri, 15 Sep 2017) $");
  script_tag(name:"creation_date", value:"2017-09-11 19:06:34 +0530 (Mon, 11 Sep 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Pulse Connect Secure Detection (SNMP)");

  script_tag(name:"summary", value:"Detection of Pulse Connect Secure.

  This script performs SNMP based detection of Pulse Connect Secure.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc");
  exit(0);
}

include("cpe.inc");
include("host_details.inc");

## Get port
snmpPort = get_kb_item("Services/udp/snmp");
if(!snmpPort) snmpPort = 161;

## Get snmp response
sysdesc = get_kb_item("SNMP/sysdesc");
if(!sysdesc) exit(0);

# Check for Pulse Connect Secure
if("Pulse Connect Secure" >< sysdesc && "Pulse Secure" >< sysdesc)
{
  model = "unknown";
  version = "unknown";
  set_kb_item(name:"Pulse/Connect/Secure/detected", value:TRUE);

  # Check for model, version, build
  details = eregmatch(pattern:"Pulse Secure, LLC,Pulse Connect Secure,(.*),(.*) \(build ([0-9]+)\)", string:sysdesc);
  if(!details){
    exit(0);
  } else {
    model = details[1];
    version = details[2];
    build = details[3];
  }

  ## Set Model
  if(model){
    set_kb_item(name:"Pulse/Connect/Secure/Model", value:model);
  }
  
  ## Set Version
  if(version){
    set_kb_item(name:"Pulse/Connect/Secure/Version", value:version);
  }

  ## Set Build
  if(build){
    set_kb_item(name:"Pulse/Connect/Secure/Build", value:build);
  }

  ##Earlier Juniper Product, formerly Juniper Junos Pulse, cpe:/a:juniper:pulse_connect_secure
  cpe = build_cpe(value:version, exp:"^([0-9a-zA-Z.]+)", base:"cpe:/a:juniper:pulse_connect_secure:" );
  if(!cpe){
    cpe = "cpe:/a:juniper:pulse_connect_secure";
  }

  ## Register Product
  register_product(cpe:cpe, port:snmpPort, service:"snmp", proto:"udp");

  ## Log the details
  log_message(data: build_detection_report(app:"Pulse Connect Secure",
                                           version:version,
                                           install:snmpPort + "/udp",
                                           cpe:cpe,
                                           concluded:sysdesc));
  exit(0);
}
exit(0);
