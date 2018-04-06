###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_beanstalkd_detect.nasl 9347 2018-04-06 06:58:53Z cfischer $
#
# Beanstalkd Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_summary = "This script finds the installed Beanstalkd version and saves
  the result in KB.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.901121");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
 script_version("$Revision: 9347 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 08:58:53 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2010-06-21 15:32:44 +0200 (Mon, 21 Jun 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Beanstalkd Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner");
  script_copyright("Copyright (C) 2010 SecPod");
  script_dependencies("find_service.nasl");
  script_family("Service detection");
  script_require_ports(11300);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("cpe.inc");
include("host_details.inc");

## Constant values
SCRIPT_OID  = "1.3.6.1.4.1.25623.1.0.901121";
SCRIPT_DESC = "Beanstalkd Version Detection";

port = "11300" ;
## Check port status
if (! get_port_state(port)) {
  exit(0);
}

## Open Socket
soc = open_sock_tcp (port);
if (!soc){
  exit (0);
}

## Send 'stats' Command and Receive response
send(socket:soc, data:raw_string(0x73,0x74,0x61,0x74,0x73,0x0d,0x0a));
buf = recv(socket:soc, length:1024);
if(!buf){
  exit(0);
}

## Grep Version from response
version = eregmatch(pattern:"version: ([0-9.]+)", string: buf);
if(version[1] != NULL)
{
  ## Set Beanstalkd Version in KB
  set_kb_item(name:"Beanstalkd/Ver", value:version[1]);
  log_message(data:"Beanstalkd version " + version[1] +
                     " was detected on the host", port:port);
      
  ## build cpe and store it as host_detail
  cpe = build_cpe(value:version[1], exp:"^([0-9.]+)", base:"cpe:/a:wildbit:beanstalkd:");
  if(!isnull(cpe))
     register_host_detail(name:"App", value:cpe, nvt:SCRIPT_OID, desc:SCRIPT_DESC);

}

