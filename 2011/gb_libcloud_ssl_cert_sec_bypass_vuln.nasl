###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_libcloud_ssl_cert_sec_bypass_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Libcloud SSL Certificates Security Bypass Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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

tag_impact = "Successful exploitation will allow attackers to spoof certificates and
  bypass intended access restrictions via a man-in-the-middle (MITM) attack.
  Impact Level: Application";
tag_affected = "libcloud version prior to 0.4.1";
tag_insight = "The flaw is due to improper verification of SSL certificates for
  HTTPS connections.";
tag_solution = "Upgrade to  libcloud version 0.4.1 or later
  For updates refer to http://libcloud.apache.org/";
tag_summary = "This host is installed with Libcloud and is prone to security
  bypass vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802164");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-09-22 10:24:03 +0200 (Thu, 22 Sep 2011)");
  script_cve_id("CVE-2010-4340");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Libcloud SSL Certificates Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://wiki.apache.org/incubator/LibcloudSSL");
  script_xref(name : "URL" , value : "https://issues.apache.org/jira/browse/LIBCLOUD-55");
  script_xref(name : "URL" , value : "http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=598463");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock){
  exit(0);
}

## Get the file location
libName = find_file(file_name:"__init__.py", file_path:"/libcloud/", 
                            useregex:TRUE, regexpar:"$", sock:sock);

## Check for the each path
if(libName)
{
  foreach binaryName (libName)
  {
    ## Get the version
    libVer = get_bin_version(full_prog_name:"cat", sock:sock,
                             version_argv:chomp(binaryName),
                             ver_pattern:"= '([0-9.]+)'");
    if(libVer[1])
    {
      ## Check the version
      if(version_is_less(version:libVer[1], test_version:"0.4.1"))
      {
        security_message(0);
        close(sock); 
        exit(0);
      }
    }
  }
}
close(sock);
