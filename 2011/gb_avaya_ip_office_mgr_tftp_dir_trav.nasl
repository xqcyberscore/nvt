###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_avaya_ip_office_mgr_tftp_dir_trav.nasl 7577 2017-10-26 10:41:56Z cfischer $
#
# Avaya IP Office Manager TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802027");
  script_version("$Revision: 7577 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 12:41:56 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Avaya IP Office Manager TFTP Server Directory Traversal Vulnerability");

  script_xref(name : "URL" , value : "http://secpod.org/blog/?p=225");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/48272");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/17507");
  script_xref(name : "URL" , value : "http://support.avaya.com/css/P8/documents/100141179");
  script_xref(name : "URL" , value : "http://secpod.org/SECPOD_Exploit-Avaya-IP-Manager-Dir-Trav.py");
  script_xref(name : "URL" , value : "http://secpod.org/advisories/SECPOD_Avaya_IP_Manager_TFTP_Dir_Trav.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);

  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to read arbitrary files on the
  affected application.
  Impact Level: Application");
  script_tag(name : "affected" , value : "Avaya IP Office Manager TFTP Server Version 8.1 and prior.");
  script_tag(name : "insight" , value : "The flaw is due to an error while handling certain requests containing
  'dot dot' sequences (..), which can be exploited to download arbitrary files
  from the host system.");
  script_tag(name : "solution" , value : "Apply the patch from below link,
  http://support.avaya.com/css/P8/documents/100141179");
  script_tag(name : "summary" , value : "The host is running Avaya IP Office Manager TFTP Server and is
  prone to directory traversal vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("tftp.inc");

## Check fot tftp service
port = get_kb_item("Services/udp/tftp");
if(!port){
  port = 69;
}

## Check Port State
if(!get_port_state(port)){
  exit(0);
}

files = traversal_files("windows");

foreach file(keys(files)) {

  ## Try The Exploit
  response = tftp_get(port:port, path:"../../../../../../../../../" +
                                      "../../../" + files[file]);
  if(isnull(response)){
    exit(0);
  }

  ## Check The response and confirm the exploit
  if (egrep(pattern:file, string:response, icase:TRUE)) {
    security_message(port: port, proto: "udp");
    exit(0);
  }
}

exit(99);