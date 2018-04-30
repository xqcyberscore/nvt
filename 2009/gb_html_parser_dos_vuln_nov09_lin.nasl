###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_html_parser_dos_vuln_nov09_lin.nasl 9657 2018-04-27 10:38:29Z cfischer $
#
# HTML-Parser 'decode_entities()' Denial of Service Vulnerability
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801039");
  script_version("$Revision: 9657 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-27 12:38:29 +0200 (Fri, 27 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-09 14:01:44 +0100 (Mon, 09 Nov 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2009-3627");
  script_bugtraq_id(36807);
  script_name("HTML-Parser 'decode_entities()' Denial of Service Vulnerability");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/37155");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/53941");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2009/10/23/9");
  script_xref(name : "URL" , value : "https://issues.apache.org/SpamAssassin/show_bug.cgi?id=6225");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_html_parser_detect_lin.nasl");
  script_require_keys("HTML-Parser/Linux/Ver");
  script_tag(name : "impact" , value : "Successful exploitation could result in Denial of service condition.
  Impact Level: Application.");
  script_tag(name : "affected" , value : "HTML-Parser versions prior to 3.63 on Linux.");
  script_tag(name : "insight" , value : "The flaw is due to an error within the 'decode_entities()' function in 'utils.c',
  which can be exploited to cause an infinite loop by tricking an application into
  processing a specially crafted string using this library.");
  script_tag(name : "summary" , value : "This host is installed with HTML-Parser and is prone to Denial of
  Service Vulnerability.");
  script_tag(name : "solution" , value : "Upgrade to HTML-Parser version 3.63 or later
  http://search.cpan.org/CPAN/authors/id/G/GA/GAAS/HTML-Parser-3.63.tar.gz
  (or)
  Apply the patch,
  http://github.com/gisle/html-parser/commit/b9aae1e43eb2c8e989510187cff0ba3e996f9a4c

  *****
  NOTE: Please ignore this warning if the patch is already applied.
  *****");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("version_func.inc");

parserVer = get_kb_item("HTML-Parser/Linux/Ver");
if(!parserVer){
  exit(0);
}

if(version_is_less(version:parserVer, test_version:"3.63")){
  security_message(0);
}
