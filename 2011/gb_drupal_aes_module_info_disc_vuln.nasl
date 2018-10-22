###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_drupal_aes_module_info_disc_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801842");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)");
  script_cve_id("CVE-2011-0899");
  script_bugtraq_id(46116);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Drupal AES Encryption Module Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://drupal.org/node/1048998");
  script_xref(name:"URL", value:"http://secunia.com/advisories/43185");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/65112");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("drupal_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");
  script_tag(name:"affected", value:"Drupal AES Encryption Module 7.x-1.4");
  script_tag(name:"insight", value:"The flaw is triggered when the module saves user passwords in a text file,
  which will disclose the password to a remote attacker who directly requests
  the file.");
  script_tag(name:"solution", value:"Upgarade to Drupal AES Encryption Module 7.x-1.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"The host is running Drupal AES Encryption Module and is prone to
  information disclosure vulnerability.");
  script_xref(name:"URL", value:"http://drupal.org/node/1040728");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!port){
  exit(0);
}

if(dir = get_dir_from_kb(port:port,app:"drupal"))
{
  req = http_get(item:string(dir, "/login_edit_dump.txt"), port:port);
  res = http_keepalive_send_recv(port:port, data:req);

  if(ereg(pattern:"^HTTP/[0-9]\.[0-9] 200 .*", string:res))
  {
    security_message(port);
    exit(0);
  }
}
