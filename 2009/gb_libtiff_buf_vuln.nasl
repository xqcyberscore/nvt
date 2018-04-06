###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libtiff_buf_vuln.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# LibTIFF TIFF Image Buffer Underflow Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com> 
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "A remote attacker could exploit this issue to execute arbitrary code
  or to crash the affected application.

  Impact level: System/Application";

tag_affected = "LibTIFF versions 3.x";
tag_insight = "The flaw is due to buffer underflow error in the 'LZWDecodeCompat()'
  [libtiff/tif_lzw.c] function when processing malicious TIFF images.";
tag_solution = "Apply the patches available.
  http://bugzilla.maptools.org/attachment.cgi?id=314";
tag_summary = "This host is installed with LibTIFF and is prone to buffer
  underflow vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800646");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2285");
  script_bugtraq_id(35451);
  script_name("LibTIFF TIFF Image Buffer Underflow Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_mandatory_keys("login/SSH/success");
  script_dependencies("gather-package-list.nasl");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_xref(name : "URL" , value : "http://secunia.com/advisories/35515/");
  script_xref(name : "URL" , value : "https://bugs.edge.launchpad.net/bugs/380149");
  script_xref(name : "URL" , value : "http://www.lan.st/showthread.php?t=1856&page=3");
  script_xref(name : "URL" , value : "http://www.vupen.com/english/advisories/2009/1637");
  exit(0);
}


include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

libtiffPaths = find_file(file_name:"config.status", file_path:"/", useregex:TRUE,
                       regexpar:"$", sock:sock);

foreach libtiffBin (libtiffPaths)
{
  libtiffVer = get_bin_version(full_prog_name:chomp(libtiffBin), sock:sock,
          version_argv:"--version", ver_pattern:"config.status ([0-9.]+)");

  if(("LibTIFF" >< libtiffVer) && (libtiffVer[1] != NULL))
  {
    if(version_in_range(version:libtiffVer[1], test_version:"3.0",
                                          test_version2:"3.8.2")){
      security_message(0);
      exit(0);
    }
  }
}
