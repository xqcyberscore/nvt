###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fedora_2017_f2df9d7772_curl_fc25.nasl 7658 2017-11-06 05:53:53Z teissa $
#
# Fedora Update for curl FEDORA-2017-f2df9d7772
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.873264");
  script_version("$Revision: 7658 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-06 06:53:53 +0100 (Mon, 06 Nov 2017) $");
  script_tag(name:"creation_date", value:"2017-08-14 07:44:47 +0200 (Mon, 14 Aug 2017)");
  script_cve_id("CVE-2017-1000100", "CVE-2017-1000101");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("Fedora Update for curl FEDORA-2017-f2df9d7772");
  script_tag(name: "summary", value: "Check the version of curl");
  script_tag(name: "vuldetect", value: "Get the installed version with the help 
of detect NVT and check if the version is vulnerable or not.");
  script_tag(name: "insight", value: "curl is a command line tool for transferring 
data with URL syntax, supporting FTP, FTPS, HTTP, HTTPS, SCP, SFTP, TFTP, TELNET, 
DICT, LDAP, LDAPS, FILE, IMAP, SMTP, POP3 and RTSP.  curl supports SSL certificates, 
HTTP POST, HTTP PUT, FTP uploading, HTTP form based upload, proxies, cookies, 
user+password authentication (Basic, Digest, NTLM, Negotiate, kerberos...), file 
transfer resume, proxy tunneling and a busload of other useful tricks.");
  script_tag(name: "affected", value: "curl on Fedora 25");
  script_tag(name: "solution", value: "Please Install the Updated Packages.");

  script_xref(name: "FEDORA", value: "2017-f2df9d7772");
  script_xref(name: "URL" , value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GPL37DFMX7KV4HFA7LZ7CXMGMTQWUKYG");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC25")
{

  if ((res = isrpmvuln(pkg:"curl", rpm:"curl~7.51.0~9.fc25", rls:"FC25")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
