###############################################################################
# OpenVAS Vulnerability Test
#
# Fedora Update for cyrus-imapd FEDORA-2011-13869
#
# Authors:
# System Generated Check
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

include("revisions-lib.inc");
tag_insight = "The cyrus-imapd package contains the core of the Cyrus IMAP server.
  It is a scalable enterprise mail system designed for use from
  small to large enterprise environments using standards-based
  internet mail technologies.

  A full Cyrus IMAP implementation allows a seamless mail and bulletin
  board environment to be set up across multiple servers. It differs from
  other IMAP server implementations in that it is run on &quot;sealed&quot;
  servers, where users are not normally permitted to log in and have no
  system account on the server. The mailbox database is stored in parts
  of the file system that are private to the Cyrus IMAP server. All user
  access to mail is through software using the IMAP, POP3 or KPOP
  protocols. It also includes support for virtual domains, NNTP,
  mailbox annotations, and much more. The private mailbox database design
  gives the server large advantages in efficiency, scalability and
  administratability. Multiple concurrent read/write connections to the
  same mailbox are permitted. The server supports access control lists on
  mailboxes and storage quotas on mailbox hierarchies.
  
  The Cyrus IMAP server supports the IMAP4rev1 protocol described
  in RFC 3501. IMAP4rev1 has been approved as a proposed standard.
  It supports any authentication mechanism available from the SASL
  library, imaps/pop3s/nntps (IMAP/POP3/NNTP encrypted using SSL and
  TLSv1) can be used for security. The server supports single instance
  store where possible when an email message is addressed to multiple
  recipients, SIEVE provides server side email filtering.";
tag_solution = "Please Install the Updated Packages.";

tag_affected = "cyrus-imapd on Fedora 14";


if(description)
{
  script_xref(name : "URL" , value : "http://lists.fedoraproject.org/pipermail/package-announce/2011-October/068024.html");
  script_oid("1.3.6.1.4.1.25623.1.0.863585");
  script_version("$Revision: 9371 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:55:06 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-10-14 14:22:41 +0200 (Fri, 14 Oct 2011)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_xref(name: "FEDORA", value: "2011-13869");
  script_cve_id("CVE-2011-3208", "CVE-2011-1926");
  script_name("Fedora Update for cyrus-imapd FEDORA-2011-13869");

  script_tag(name:"summary", value:"Check for the Version of cyrus-imapd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");


res = "";
if(release == NULL){
  exit(0);
}

if(release == "FC14")
{

  if ((res = isrpmvuln(pkg:"cyrus-imapd", rpm:"cyrus-imapd~2.3.18~1.fc14", rls:"FC14")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
