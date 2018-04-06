###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_aes_module_info_disc_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Drupal AES Encryption Module Information Disclosure Vulnerability
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

tag_impact = "Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.
  Impact Level: Application";
tag_affected = "Drupal AES Encryption Module 7.x-1.4";
tag_insight = "The flaw is triggered when the module saves user passwords in a text file,
  which will disclose the password to a remote attacker who directly requests
  the file.";
tag_solution = "Upgarade to Drupal AES Encryption Module 7.x-1.5 or later.
  For updates refer to http://drupal.org/node/1040728";
tag_summary = "The host is running Drupal AES Encryption Module and is prone to
  information disclosure vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801842");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2011-0899");
  script_bugtraq_id(46116);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Drupal AES Encryption Module Information Disclosure Vulnerability");
  script_xref(name : "URL" , value : "http://drupal.org/node/1048998");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/43185");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/65112");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
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

if(dir = get_dir_from_kb(port:port,app:"drupal"))
{
  ## Try to access login_edit_dump.txt
  req = http_get(item:string(dir, "/login_edit_dump.txt"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  ## Check for the file status
  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res))
  {
    security_message(port);
    exit(0);
  }
}
