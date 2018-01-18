###############################################################################
# OpenVAS Vulnerabilities Test
# $Id: gb_libesmtp_mult_vuln.nasl 8440 2018-01-17 07:58:46Z teissa $
#
# libESMTP multiple vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_summary = "This host has libESMTP installed and is prone to multiple
  vulnerabilities.

  Vulnerabilities Insight:
  Multiple flaws are due to:
  - An error in 'match_component()' function in 'smtp-tls.c' when processing
    substrings. It treats two strings as equal if one is a substring of the
    other, which allows attackers to spoof trusted certificates via a crafted
    subjectAltName.
  - An error in handling of 'X.509 certificate'. It does not properly
    handle a '&qt?&qt' character in a domain name in the 'subject&qts Common Name'
    field of an X.509 certificate, which allows man-in-the-middle attackers to
    spoof arbitrary SSL servers via a crafted certificate.";

tag_solution = "Apply patch from below links,
  https://bugzilla.redhat.com/attachment.cgi?id=399131&action=edit
  https://bugzilla.redhat.com/attachment.cgi?id=398839&action=edit

  *****
  NOTE: Ignore this warning, if above mentioned patch is manually applied.
  *****";

tag_impact = "Attackers can exploit this issue to conduct man-in-the-middle attacks to
  spoof arbitrary SSL servers and to spoof trusted certificates.
  Impact Level: Application";
tag_affected = "libESMTP version 1.0.4 and prior.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800497");
  script_version("$Revision: 8440 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-17 08:58:46 +0100 (Wed, 17 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-04-06 08:47:09 +0200 (Tue, 06 Apr 2010)");
  script_cve_id("CVE-2010-1194", "CVE-2010-1192");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("libESMTP multiple vulnerabilities");

  script_xref(name : "URL" , value : "https://bugzilla.redhat.com/show_bug.cgi?id=571817");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/03/09/3");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/03/03/6");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_libesmtp_detect.nasl");
  script_require_keys("libESMTP/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

libesmtpVer = get_kb_item("libESMTP/Ver");
if(libesmtpVer != NULL)
{
  if(version_is_less_equal(version:libesmtpVer, test_version:"1.0.4")){
    security_message(0);
  }
}
