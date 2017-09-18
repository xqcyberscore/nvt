###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_tivoli_dir_server_detect.nasl 7133 2017-09-14 14:31:13Z cfischer $
#
# IBM Tivoli Directory Server Version Detection
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
#
# Updated By : Sooraj KS <kssooraj@secpod.com> on 2011-04-27
# Updated to detect latest versions.
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801812");
  script_version("$Revision: 7133 $");
  script_tag(name:"last_modification", value:"$Date: 2017-09-14 16:31:13 +0200 (Thu, 14 Sep 2017) $");
  script_tag(name:"creation_date", value:"2011-01-21 14:38:54 +0100 (Fri, 21 Jan 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("IBM Tivoli Directory Server Version Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("ldap_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("ldap/detected");

  script_tag(name:"summary", value:"This script finds the running IBM Tivoli Directory Server version
  and saves the result in KB.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ldap.inc");
include("cpe.inc");
include("host_details.inc");

SCRIPT_DESC = "IBM Tivoli Directory Server Version Detection";

port = get_ldap_port( default:389 );

## LDAP searchMessage Request Payload
req = raw_string(0x30, 0x84, 0x00, 0x00, 0x00, 0x2d, 0x02, 0x01,
                 0x0e, 0x63, 0x84, 0x00, 0x00, 0x00, 0x24, 0x04,
                 0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
                 0x01, 0x00, 0x02, 0x01, 0x01, 0x01, 0x01, 0x00,
                 0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
                 0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x84, 0x00,
                 0x00, 0x00, 0x00);

## Open TCP Socket
soc = open_sock_tcp(port);
if(!soc) {
  exit(0);
}

## Sending Request
send(socket:soc, data:req);
result = recv(socket:soc, length:2000);
close(soc);

## Confirm the IBM Tivoli Directory Server
if("International Business Machines" >< result && "ibmdirectoryversion1" >< result)
{
  ## Extract Version From Response
  index = stridx(result, "ibmdirectoryversion1");
  if (index == -1){
    exit(0);
  }

  version = substr(result, index+22, index+36);
  len = strlen(version);
  for(i = 0; i < len; i++)
  {
    if(version[i] =~ '[0-9.]'){
      tdsVer = tdsVer + version[i];
    }
  }

  if(tdsVer)
  {
    ## Set IBM Tivoli Directory Server Version in KB
    set_kb_item(name:"IBM/TDS/Ver",value:tdsVer);
    log_message(port:port, data:"Tivoli Directory Server version " + tdsVer +
                       " was detected on the host");
      
    ## build cpe and store it as host_detail
    cpe = build_cpe(value:tdsVer, exp:"^([0-9.]+)", base:"cpe:/a:ibm:tivoli_directory_server:");
    if(!isnull(cpe))
       register_host_detail(name:"App", value:cpe, desc:SCRIPT_DESC);

  }
}
