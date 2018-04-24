###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_snmp_agents_detect_lin.nasl 9584 2018-04-24 10:34:07Z jschulte $
#
# HP SNMP Agents Version Detection (Linux)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "Detection of installed version of HP SNMP Agents.

The script logs in via ssh, searches for HP SNMP Agents from the list of
installed rpm packages and gets the version";

SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.802769";

if(description)
{
  script_oid(SCRIPT_OID);
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9584 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-24 12:34:07 +0200 (Tue, 24 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-05-08 12:53:44 +0530 (Tue, 08 May 2012)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("HP SNMP Agents Version Detection (Linux)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rpms", "login/SSH/success");

  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");
include("cpe.inc");
include("host_details.inc");

## Variable Initialization
sock = 0;
result = "";
version = "";
cpe = NULL;
buffer_rpm = NULL;

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(-1);
}

## Trying to get version from rpm
buffer_rpm = get_kb_item("ssh/login/rpms");
if(buffer_rpm != NULL && buffer_rpm =~ "hp-snmp-agents")
{
  ## Grep for the version
  version = eregmatch(pattern:"hp-snmp-agents.?([0-9.]+)", string:buffer_rpm);
  if(version[1])
  {
    path ="/opt/hp/hp-snmp-agents/";

    ## Set the KB item
    set_kb_item(name:"HP/SNMP/Agents", value:version[1]);
    cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:hp:snmp_agents_for_linux:");
    if(!isnull(cpe))
      register_product(cpe:cpe, location:path);

    log_message(data: build_detection_report(app:"HP SNMP Agents",
                                         version:version[1],
                                         install:path,
                                         cpe:cpe,
                                         concluded: version[1]));
  }
}

close(sock);
