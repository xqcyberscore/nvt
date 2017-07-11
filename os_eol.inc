###############################################################################
# OpenVAS Include File
# $Id: os_eol.inc 6425 2017-06-24 08:33:41Z cfischer $
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

eol_urls = make_array();
eol_cpes = make_array();

# See gather-package-list.nasl for valid/known linux cpes

# OpenSUSE (http://en.opensuse.org/Lifetime)
eol_urls['cpe:/o:novell:opensuse'] = 'http://en.opensuse.org/Lifetime';
eol_cpes['cpe:/o:novell:opensuse:13.2'] = '17 Jan 2017';
eol_cpes['cpe:/o:novell:opensuse:13.1'] = '03 Feb 2016';
eol_cpes['cpe:/o:novell:opensuse:12.3'] = '29 Jan 2015';
eol_cpes['cpe:/o:novell:opensuse:12.2'] = '15 Jan 2014';
eol_cpes['cpe:/o:novell:opensuse:12.1'] = '15 May 2013';
eol_cpes['cpe:/o:novell:opensuse:11.4'] = '05 Nov 2012';
eol_cpes['cpe:/o:novell:opensuse:11.3'] = '20 Jan 2012';
eol_cpes['cpe:/o:novell:opensuse:11.2'] = '12 May 2011';
eol_cpes['cpe:/o:novell:opensuse:11.1'] = '31 Dec 2010';
eol_cpes['cpe:/o:novell:opensuse:11.0'] = '30 Jun 2010';
eol_cpes['cpe:/o:novell:opensuse:10.3'] = '31 Oct 2009';
eol_cpes['cpe:/o:novell:opensuse:10.2'] = '30 Nov 2008';

# SUSE Linux (http://en.opensuse.org/Lifetime)
eol_urls['cpe:/o:novell:suse_linux'] = 'http://en.opensuse.org/Lifetime';
eol_cpes['cpe:/o:novell:suse_linux:10.1'] = '31 May 2008';
eol_cpes['cpe:/o:novell:suse_linux:10.0'] = '30 Nov 2007';
eol_cpes['cpe:/o:novell:suse_linux:9.3'] = '30 Apr 2007';
eol_cpes['cpe:/o:novell:suse_linux:9.2'] = '31 Oct 2006';
eol_cpes['cpe:/o:novell:suse_linux:9.1'] = '30 Jun 2006';
eol_cpes['cpe:/o:novell:suse_linux:9.0'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:8.2'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:8.1'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:novell:suse_linux:7.3'] = 'unknown';

# SLES (http://www.softpanorama.org/Commercial_linuxes/Suse/sles_life_cycle.shtml)
eol_urls['cpe:/o:suse:linux_enterprise_server'] = 'http://www.softpanorama.org/Commercial_linuxes/Suse/sles_life_cycle.shtml';
eol_cpes['cpe:/o:suse:linux_enterprise_server:10'] = '31 Jul 2016';
eol_cpes['cpe:/o:suse:linux_enterprise_server:9'] = '31 Jul 2011';

# Ubuntu (https://wiki.ubuntu.com/Releases)
eol_urls['cpe:/o:canonical:ubuntu_linux'] = 'https://wiki.ubuntu.com/Releases';
eol_cpes['cpe:/o:canonical:ubuntu_linux:15.10'] = '28 Jul 2016';
eol_cpes['cpe:/o:canonical:ubuntu_linux:15.04'] = '04 Feb 2016';
eol_cpes['cpe:/o:canonical:ubuntu_linux:14.10'] = '23 Jul 2014';
eol_cpes['cpe:/o:canonical:ubuntu_linux:13.10'] = '17 Jul 2014';
eol_cpes['cpe:/o:canonical:ubuntu_linux:13.04'] = '27 Jan 2014';
eol_cpes['cpe:/o:canonical:ubuntu_linux:12.10'] = '16 May 2014';
eol_cpes['cpe:/o:canonical:ubuntu_linux:12.04'] = '28 Apr 2017';
eol_cpes['cpe:/o:canonical:ubuntu_linux:11.10'] = '09 May 2013';
eol_cpes['cpe:/o:canonical:ubuntu_linux:11.04'] = '28 Oct 2012';
eol_cpes['cpe:/o:canonical:ubuntu_linux:10.10'] = '10 Apr 2012';
eol_cpes['cpe:/o:canonical:ubuntu_linux:10.04'] = '30 Apr 2015';
eol_cpes['cpe:/o:canonical:ubuntu_linux:9.10']  = '30 Apr 2011';
eol_cpes['cpe:/o:canonical:ubuntu_linux:9.04']  = '23 Oct 2010';
eol_cpes['cpe:/o:canonical:ubuntu_linux:8.10']  = '12 May 2011';
eol_cpes['cpe:/o:canonical:ubuntu_linux:8.04']  = '09 May 2013';
eol_cpes['cpe:/o:canonical:ubuntu_linux:7.10']  = '18 Apr 2009';
eol_cpes['cpe:/o:canonical:ubuntu_linux:7.04']  = '19 Oct 2008';
eol_cpes['cpe:/o:canonical:ubuntu_linux:6.10']  = '26 Apr 2008';
eol_cpes['cpe:/o:canonical:ubuntu_linux:6.06']  = '14 Jul 2009';
eol_cpes['cpe:/o:canonical:ubuntu_linux:5.10']  = '13 Apr 2007';
eol_cpes['cpe:/o:canonical:ubuntu_linux:5.04']  = '31 Oct 2006';
eol_cpes['cpe:/o:canonical:ubuntu_linux:4.10']  = '30 Apr 2006';

# Red Hat Enterprise Linux (https://access.redhat.com/security/updates/eol/)
eol_urls['cpe:/o:redhat:enterprise_linux'] = 'https://access.redhat.com/security/updates/eol/';
eol_cpes['cpe:/o:redhat:enterprise_linux:4'] = 'unknown';
eol_cpes['cpe:/o:redhat:enterprise_linux:3'] = 'unknown';
eol_cpes['cpe:/o:redhat:enterprise_linux:2.1'] = 'unknown';

# Redhat Linux (https://en.wikipedia.org/wiki/Red_Hat_Linux#Version_history)
eol_urls['cpe:/o:redhat:linux'] = 'https://en.wikipedia.org/wiki/Red_Hat_Linux#Version_history';
eol_cpes['cpe:/o:redhat:linux:9'] = 'unknown';
eol_cpes['cpe:/o:redhat:linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:redhat:linux:7.3'] = 'unknown';

# CentOS (http://wiki.centos.org/Download)
eol_urls['cpe:/o:centos:centos'] = 'http://wiki.centos.org/Download';
eol_cpes['cpe:/o:centos:centos:5'] = '31 Mar 2017';
eol_cpes['cpe:/o:centos:centos:4'] = '29 Feb 2012';
eol_cpes['cpe:/o:centos:centos:3'] = '31 Oct 2010';
eol_cpes['cpe:/o:centos:centos:2'] = '31 May 2009';

# Fedora (https://fedoraproject.org/wiki/End_of_life?rd=LifeCycle/EOL)
eol_urls['cpe:/o:fedoraproject:fedora'] = 'https://fedoraproject.org/wiki/End_of_life?rd=LifeCycle/EOL';
eol_cpes['cpe:/o:fedoraproject:fedora:23'] = '20 Dec 2016';
eol_cpes['cpe:/o:fedoraproject:fedora:22'] = '19 Jul 2016';
eol_cpes['cpe:/o:fedoraproject:fedora:21'] = '01 Dec 2015';
eol_cpes['cpe:/o:fedoraproject:fedora:20'] = '23 Jun 2015';
eol_cpes['cpe:/o:fedoraproject:fedora:19'] = '06 Jan 2015';
eol_cpes['cpe:/o:fedoraproject:fedora:18'] = '14 Jan 2014';
eol_cpes['cpe:/o:fedoraproject:fedora:17'] = '30 Jul 2013';
eol_cpes['cpe:/o:fedoraproject:fedora:16'] = '12 Feb 2013';
eol_cpes['cpe:/o:fedoraproject:fedora:15'] = '26 Jun 2012';
eol_cpes['cpe:/o:fedoraproject:fedora:14'] = '09 Dec 2011';
eol_cpes['cpe:/o:fedoraproject:fedora:13'] = '24 Jun 2011';
eol_cpes['cpe:/o:fedoraproject:fedora:12'] = '12 Feb 2010';
eol_cpes['cpe:/o:fedoraproject:fedora:11'] = '25 Jun 2010';
eol_cpes['cpe:/o:fedoraproject:fedora:10'] = '19 Dec 2009';
eol_cpes['cpe:/o:fedoraproject:fedora:9']  = '10 Jul 2009';
eol_cpes['cpe:/o:fedoraproject:fedora:8']  = '07 Jan 2009';
eol_cpes['cpe:/o:fedoraproject:fedora:7']  = '13 Jun 2008';
eol_cpes['cpe:/o:fedoraproject:fedora_core:6'] = '27 Dec 2007';
eol_cpes['cpe:/o:fedoraproject:fedora_core:5'] = '02 Jul 2007';
eol_cpes['cpe:/o:fedoraproject:fedora_core:4'] = '07 Aug 2006';
eol_cpes['cpe:/o:fedoraproject:fedora_core:3'] = '16 Jan 2006';
eol_cpes['cpe:/o:fedoraproject:fedora_core:2'] = '11 Apr 2005';
eol_cpes['cpe:/o:fedoraproject:fedora_core:1'] = '20 Sep 2004';

# Debian # (https://en.wikipedia.org/wiki/List_of_Debian_releases#Release_table)
eol_urls['cpe:/o:debian:debian_linux'] = 'https://en.wikipedia.org/wiki/List_of_Debian_releases#Release_table';
eol_cpes['cpe:/o:debian:debian_linux:6.0'] = '29 Feb 2016';
eol_cpes['cpe:/o:debian:debian_linux:5.0'] = '06 Feb 2012';
eol_cpes['cpe:/o:debian:debian_linux:4.0'] = '15 Feb 2010';
eol_cpes['cpe:/o:debian:debian_linux:3.1'] = '31 Mar 2008';
eol_cpes['cpe:/o:debian:debian_linux:3.0'] = '30 Jun 2006';
eol_cpes['cpe:/o:debian:debian_linux:2.2'] = '30 Jun 2003';
eol_cpes['cpe:/o:debian:debian_linux:2.1'] = '30 Oct 2000';
eol_cpes['cpe:/o:debian:debian_linux:2.0'] = 'unknown';
eol_cpes['cpe:/o:debian:debian_linux:1.3'] = 'unknown';
eol_cpes['cpe:/o:debian:debian_linux:1.2'] = 'unknown';
eol_cpes['cpe:/o:debian:debian_linux:1.1'] = 'unknown';

# Mandriva (https://en.wikipedia.org/wiki/Mandriva_Linux#Table_of_versions)
eol_urls['cpe:/o:mandriva:linux'] = 'https://en.wikipedia.org/wiki/Mandriva_Linux#Table_of_versions';
eol_cpes['cpe:/o:mandriva:linux:2011.0'] = '29 Feb 2013';
eol_cpes['cpe:/o:mandriva:linux:2010.2'] = 'unknown';
eol_cpes['cpe:/o:mandriva:linux:2010.1'] = '08 Jul 2012';
eol_cpes['cpe:/o:mandriva:linux:2010.0'] = '03 Nov 2012';
eol_cpes['cpe:/o:mandriva:linux:2009.1'] = '29 Oct 2010';
eol_cpes['cpe:/o:mandriva:linux:2009.0'] = '15 Oct 2011';
eol_cpes['cpe:/o:mandriva:linux:2008.1'] = '15 Oct 2009';
eol_cpes['cpe:/o:mandriva:linux:2008.0'] = '09 Oct 2010';
eol_cpes['cpe:/o:mandriva:linux:2007.1'] = 'unknown';
eol_cpes['cpe:/o:mandriva:linux:2007.0'] = 'unknown';
eol_cpes['cpe:/o:mandriva:linux:2006.0'] = 'unknown';
eol_cpes['cpe:/o:mandriva:enterprise_server:5.2'] = 'unknown';
eol_cpes['cpe:/o:mandriva:enterprise_server:5.1'] = 'unknown';
eol_cpes['cpe:/o:mandriva:enterprise_server:5.0'] = 'unknown';
eol_cpes['cpe:/o:mandriva:enterprise_server:5'] = 'unknown';

# Mandrake
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:10.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:10.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.2'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:9.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.2'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.1'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:mandrakesoft:mandrake_linux:7.2'] = 'unknown';

# Mageia (https://en.wikipedia.org/wiki/Mageia#Version_history)
eol_urls['cpe:/o:mageia:linux'] = 'https://en.wikipedia.org/wiki/Mageia#Version_history';
eol_cpes['cpe:/o:mageia:linux:4.1'] = '19 Sep 2015';
eol_cpes['cpe:/o:mageia:linux:4'] = '19 Sep 2015';
eol_cpes['cpe:/o:mageia:linux:3'] = '26 Nov 2014';
eol_cpes['cpe:/o:mageia:linux:2'] = '22 Nov 2013';
eol_cpes['cpe:/o:mageia:linux:1'] = '01 Dec 2012';

# Slackware (https://en.wikipedia.org/wiki/Slackware#Releases)
eol_urls['cpe:/o:slackware:slackware_linux'] = 'https://en.wikipedia.org/wiki/Slackware#Releases';
eol_cpes['cpe:/o:slackware:slackware_linux:12.2'] = '09 Dec 2013';
eol_cpes['cpe:/o:slackware:slackware_linux:12.1'] = '09 Dec 2013';
eol_cpes['cpe:/o:slackware:slackware_linux:12.0'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:11.0'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:10.2'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:10.1'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:10.0'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:9.1'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:9.0'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:8.1'] = '01 Feb 2012';
eol_cpes['cpe:/o:slackware:slackware_linux:8.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:7.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:7.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:4.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.9'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.6'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.5'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.4'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.3'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.2'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:3.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.3'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.2'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:2.0'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:1.1'] = 'unknown';
eol_cpes['cpe:/o:slackware:slackware_linux:1.00'] = 'unknown';

# Connectiva Linux (https://de.wikipedia.org/wiki/Conectiva#Versionen)
eol_urls['cpe:/a:connectiva:linux'] = 'https://de.wikipedia.org/wiki/Conectiva#Versionen';
eol_cpes['cpe:/a:connectiva:linux:10.0'] = 'unknown';
eol_cpes['cpe:/a:connectiva:linux:9.0'] = 'unknown';

# Univention Corporate Server (http://wiki.univention.de/index.php?title=Maintenance_Cycle_for_UCS)
eol_urls['cpe:/o:univention:corporate_server'] = 'http://wiki.univention.de/index.php?title=Maintenance_Cycle_for_UCS';
eol_cpes['cpe:/o:univention:corporate_server:3.1'] = '31 May 2014';
eol_cpes['cpe:/o:univention:corporate_server:3.0'] = '30 Jun 2013';
eol_cpes['cpe:/o:univention:corporate_server:2.4'] = '31 Dec 2013';
eol_cpes['cpe:/o:univention:corporate_server:2.3'] = 'unknown';
eol_cpes['cpe:/o:univention:corporate_server:2.2'] = 'unknown';
eol_cpes['cpe:/o:univention:corporate_server:2.1'] = 'unknown';
eol_cpes['cpe:/o:univention:corporate_server:2.0'] = 'unknown';

# Trustix
eol_urls['cpe:/o:trustix:secure_linux'] = 'https://en.wikipedia.org/wiki/Trustix';
eol_cpes['cpe:/o:trustix:secure_linux:3.0.5'] = '31 Dec 2007';
eol_cpes['cpe:/o:trustix:secure_linux:3.0'] = '31 Dec 2007';
eol_cpes['cpe:/o:trustix:secure_linux:2.2'] = '31 Dec 2007';
eol_cpes['cpe:/o:trustix:secure_linux:2.1'] = '31 Dec 2007';
eol_cpes['cpe:/o:trustix:secure_linux:2.0'] = '31 Dec 2007';
eol_cpes['cpe:/o:trustix:secure_linux:1.5'] = '31 Dec 2007';
eol_cpes['cpe:/o:trustix:secure_linux:1.2'] = '31 Dec 2007';
eol_cpes['cpe:/o:trustix:secure_linux:1.1'] = '31 Dec 2007';

# HP-UX
eol_urls['cpe:/o:hp:hp-ux'] = 'https://ssl.www8.hp.com/h20195/V2/GetDocument.aspx?docname=4AA4-7673ENW&cc=us&lc=en';
eol_cpes['cpe:/o:hp:hp-ux:11.00'] = 'Dec 2006';
eol_cpes['cpe:/o:hp:hp-ux:10.30'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.26'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.24'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.20'] = 'Jun 2003';
eol_cpes['cpe:/o:hp:hp-ux:10.10'] = 'unknown';
eol_cpes['cpe:/o:hp:hp-ux:10.01'] = 'unknown';

# FortiOS (https://www.boll.ch/fortinet/assets/LifeCycleStatus.pdf)
eol_urls['cpe:/o:fortinet:fortios'] = 'https://www.boll.ch/fortinet/assets/LifeCycleStatus.pdf';
eol_cpes['cpe:/o:fortinet:fortios:4.2'] = '01 Apr 2013';
eol_cpes['cpe:/o:fortinet:fortios:4.1'] = '24 Aug 2012';
eol_cpes['cpe:/o:fortinet:fortios:4.0'] = '24 Feb 2012';
eol_cpes['cpe:/o:fortinet:fortios:3.7'] = '18 Jul 2011';
eol_cpes['cpe:/o:fortinet:fortios:3.6'] = '04 Feb 2011';
eol_cpes['cpe:/o:fortinet:fortios:3.5'] = '03 Jul 2010';
eol_cpes['cpe:/o:fortinet:fortios:3.4'] = '29 Dec 2009';
eol_cpes['cpe:/o:fortinet:fortios:3.3'] = '02 Oct 2009';

# Xenserver (https://www.citrix.de/support/product-lifecycle/product-matrix.html)
eol_urls['cpe:/a:citrix:xenserver'] = 'https://www.citrix.de/support/product-lifecycle/product-matrix.html';
eol_cpes['cpe:/a:citrix:xenserver:5.6'] = '31 Mar 2014';
eol_cpes['cpe:/a:citrix:xenserver:5.5'] = '15 Sep 2013';
eol_cpes['cpe:/a:citrix:xenserver:5.0'] = '15 Sep 2013';

# Cisco IOS XR (http://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xr-software/eos-eol-notice-listing.html)
eol_urls['cpe:/o:cisco:ios_xr'] = 'http://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xr-software/eos-eol-notice-listing.html';
eol_cpes['cpe:/o:cisco:ios_xr:4.2'] = '15 Feb 2016';
eol_cpes['cpe:/o:cisco:ios_xr:4.1'] = '19 Mar 2016 ';
eol_cpes['cpe:/o:cisco:ios_xr:4.0'] = '01 Oct 2014 ';
eol_cpes['cpe:/o:cisco:ios_xr:3.9'] = '09 Apr 2012 ';
eol_cpes['cpe:/o:cisco:ios_xr:3.8'] = '28 Dec 2013 ';
eol_cpes['cpe:/o:cisco:ios_xr:3.6'] = '30 Jun 2012 ';
eol_cpes['cpe:/o:cisco:ios_xr:3.5'] = '11 May 2012 ';
eol_cpes['cpe:/o:cisco:ios_xr:3.4'] = '31 Dec 2011 ';
eol_cpes['cpe:/o:cisco:ios_xr:3.3'] = '31 Dec 2011';

# FreeBSD (https://www.freebsd.org/security/unsupported.html)
eol_urls['cpe:/o:freebsd:freebsd'] = 'https://www.freebsd.org/security/unsupported.html';
eol_cpes['cpe:/o:freebsd:freebsd:4'] = '31 Jan 2007';
eol_cpes['cpe:/o:freebsd:freebsd:4.11'] = '31 Jan 2007';
eol_cpes['cpe:/o:freebsd:freebsd:5'] = '31 May 2008';
eol_cpes['cpe:/o:freebsd:freebsd:5.3'] = '31 Oct 2006';
eol_cpes['cpe:/o:freebsd:freebsd:5.4'] = '31 Oct 2006';
eol_cpes['cpe:/o:freebsd:freebsd:5.5'] = '31 May 2008';
eol_cpes['cpe:/o:freebsd:freebsd:6'] = '30 Nov 2010';
eol_cpes['cpe:/o:freebsd:freebsd:6.0'] = '31 Jan 2007';
eol_cpes['cpe:/o:freebsd:freebsd:6.1'] = '31 May 2008';
eol_cpes['cpe:/o:freebsd:freebsd:6.2'] = '31 May 2008';
eol_cpes['cpe:/o:freebsd:freebsd:6.3'] = '31 Jan 2010';
eol_cpes['cpe:/o:freebsd:freebsd:6.4'] = '30 Nov 2010';
eol_cpes['cpe:/o:freebsd:freebsd:7'] = '28 Feb 2013';
eol_cpes['cpe:/o:freebsd:freebsd:7.0'] = '30 Apr 2009';
eol_cpes['cpe:/o:freebsd:freebsd:7.1'] = '28 Feb 2011';
eol_cpes['cpe:/o:freebsd:freebsd:7.2'] = '30 Jun 2010';
eol_cpes['cpe:/o:freebsd:freebsd:7.3'] = '31 Mar 2012';
eol_cpes['cpe:/o:freebsd:freebsd:7.4'] = '28 Feb 2013';
eol_cpes['cpe:/o:freebsd:freebsd:8'] = '01 Aug 2015';
eol_cpes['cpe:/o:freebsd:freebsd:8.0'] = '30 Nov 2010';
eol_cpes['cpe:/o:freebsd:freebsd:8.1'] = '31 Jul 2012';
eol_cpes['cpe:/o:freebsd:freebsd:8.2'] = '31 Jul 2012';
eol_cpes['cpe:/o:freebsd:freebsd:8.3'] = '30 Apr 2014';
eol_cpes['cpe:/o:freebsd:freebsd:8.4'] = '01 Aug 2015';
eol_cpes['cpe:/o:freebsd:freebsd:9'] = '31 Dec 2016';
eol_cpes['cpe:/o:freebsd:freebsd:9.0'] = '31 Mar 2013';
eol_cpes['cpe:/o:freebsd:freebsd:9.1'] = '31 Dec 2014';
eol_cpes['cpe:/o:freebsd:freebsd:9.2'] = '31 Dec 2014';
eol_cpes['cpe:/o:freebsd:freebsd:9.3'] = '31 Dec 2016';
# eol_cpes['cpe:/o:freebsd:freebsd:10.0'] = '28 Feb 2015'; # nb: Don't add 10.0 for now as gb_ssh_os_detection.nasl can't detect the differences between 10.x and would throw false positives
eol_cpes['cpe:/o:freebsd:freebsd:10.1'] = '31 Dec 2016';
eol_cpes['cpe:/o:freebsd:freebsd:10.2'] = '31 Dec 2016';

# NetBSD (https://en.wikipedia.org/wiki/NetBSD#Releases)
eol_urls['cpe:/o:netbsd:netbsd'] = 'https://en.wikipedia.org/wiki/NetBSD#Releases';
eol_cpes['cpe:/o:netbsd:netbsd:0.8'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:0.9'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.0'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.1'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.2'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.3'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.4'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.5'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:1.6'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:2.0'] = 'unknown';
eol_cpes['cpe:/o:netbsd:netbsd:3.0'] = '30 May 2009';
eol_cpes['cpe:/o:netbsd:netbsd:4.0'] = '17 Nov 2012';
eol_cpes['cpe:/o:netbsd:netbsd:5.0'] = '09 Nov 2015';

# OpenBSD (https://en.wikipedia.org/wiki/OpenBSD_version_history)
eol_urls['cpe:/o:openbsd:openbsd'] = 'https://en.wikipedia.org/wiki/OpenBSD_version_history';
eol_cpes['cpe:/o:openbsd:openbsd:1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:1.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:1.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.5'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.6'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.7'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.8'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:2.9'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.5'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.6'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.7'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.8'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:3.9'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.3'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.4'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.5'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.6'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.7'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.8'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:4.9'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5'] = '11 Apr 2017';
eol_cpes['cpe:/o:openbsd:openbsd:5.0'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5.1'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5.2'] = 'unknown';
eol_cpes['cpe:/o:openbsd:openbsd:5.3'] = '01 May 2014';
eol_cpes['cpe:/o:openbsd:openbsd:5.4'] = '01 Nov 2014';
eol_cpes['cpe:/o:openbsd:openbsd:5.5'] = '01 May 2015';
eol_cpes['cpe:/o:openbsd:openbsd:5.6'] = '18 Oct 2015';
eol_cpes['cpe:/o:openbsd:openbsd:5.7'] = '29 Mar 2016';
eol_cpes['cpe:/o:openbsd:openbsd:5.8'] = '01 Sep 2016';
eol_cpes['cpe:/o:openbsd:openbsd:5.9'] = '11 Apr 2017';

# Greenbone OS (http://greenbone.net/technology/gos_old_releases.html)
eol_urls['cpe:/o:greenbone:greenbone_os'] = 'http://greenbone.net/technology/gos_old_releases.html';
eol_cpes['cpe:/o:greenbone:greenbone_os:3.0'] = '03 Oct 2015';
eol_cpes['cpe:/o:greenbone:greenbone_os:2.2.0'] = '03 Jan 2016';
eol_cpes['cpe:/o:greenbone:greenbone_os:2.1.0'] = '31 May 2014';
eol_cpes['cpe:/o:greenbone:greenbone_os:2.0.0'] = '31 Jan 2014';
eol_cpes['cpe:/o:greenbone:greenbone_os:1.7.0'] = '30 Jun 2013';
eol_cpes['cpe:/o:greenbone:greenbone_os:1.6.0'] = 'unknown';


# General notes for windows: https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet

#Windows for Workgroups 3.1 (https://support.microsoft.com/en-us/lifecycle/?p1=3127)
eol_urls['cpe:/o:microsoft:windows:3.1'] = 'https://support.microsoft.com/en-us/lifecycle/?p1=3127';
eol_cpes['cpe:/o:microsoft:windows:3.1'] = '31 Dec 2001';

#Windows for Workgroups 3.11 (https://support.microsoft.com/en-us/lifecycle/?p1=3128)
eol_urls['cpe:/o:microsoft:windows:3.11'] = 'https://support.microsoft.com/en-us/lifecycle/?p1=3128';
eol_cpes['cpe:/o:microsoft:windows:3.11'] = '31 Dec 2001';

#Windows 95 (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+95&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_95'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+95&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_95'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::gold'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::osr2'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::osr2.1'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::osr2.5'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::sp1'] = '31 Dec 2001';
eol_cpes['cpe:/o:microsoft:windows_95::sr2'] = '31 Dec 2001';

#Windows 98 (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+98&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_98'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+98&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_98'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_98::beta'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_98::gold'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_98::scd'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_98:beta'] = '11 Jul 2006';
eol_cpes['cpe:/a:microsoft:windows_98_plus_pack'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_98se'] = '11 Jul 2006';

#Windows Millennium Edition (httpen-us://support.microsoft.com/en-us/lifecycle/?p1=6519)
eol_cpes['cpe:/o:microsoft:windows_me'] = 'httpen-us://support.microsoft.com/en-us/lifecycle/?p1=6519';
eol_cpes['cpe:/o:microsoft:windows_me'] = '11 Jul 2006';
eol_cpes['cpe:/o:microsoft:windows_me::gold'] = '11 Jul 2006';

#Windows NT (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+NT&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_nt'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+NT&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_nt:3.0.1'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:3.1'] = '31 Dec 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5'] = 'unknown';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp1'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp2'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp3'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp4'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp5'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.5.1:sp5:alpha'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:3.51'] = '30 Sep 2000';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:gold:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp1:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp2:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp3:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp4:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp5:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sp6a:workstation'] = '30 Jun 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:embedded'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:enterprise'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:terminal_server'] = '31 Dec 2002';
eol_cpes['cpe:/o:microsoft:windows_nt:4.0:sru:workstation'] = '30 Jun 2002';

#Windows 2000 (https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+2000&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_2000'] = 'https://support.microsoft.com/en-us/lifecycle/search/default.aspx?sort=PN&alpha=Windows+2000&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_2000'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::beta3'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::gold:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::rc1'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::rc2'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp1:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp2:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp3:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:advanced_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:datacenter_server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:professional'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000::sp4:server'] = '13 Jul 2010';
eol_cpes['cpe:/o:microsoft:windows_2000:beta3'] = '13 Jul 2010';

#Windows XP (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20XP&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_xp'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20XP&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_xp'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:::x64'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:::x86'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::gold'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:embedded'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:media_center'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:professional'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::gold:tablet_pc'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:embedded'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:media_center'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:professional'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp1:tablet_pc'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:embedded'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:media_center'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:professional'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:tablet_pc'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp2:x86'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp3'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp::sp3:x86'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:64-bit-2002'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:64-bit-2003'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:home'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:gold:x64'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp1:home'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp1:x64'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp2:home'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp2:x64'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:embedded'] = '12 Jan 2016';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:home'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:media_center'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:professional'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:-:sp3:tablet_pc'] = '08 Apr 2014';
eol_cpes['cpe:/o:microsoft:windows_xp:sp3:unknown:english'] = '08 Apr 2014';

#Windows 2003 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_2003_server'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_2003_server'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:compute_cluster'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:datacenter'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:enterprise'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:itanium'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:standard'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:storage'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64-datacenter'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64-enterprise'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::gold:x64-standard'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:compute_cluster'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:datacenter'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:enterprise'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:standard'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:storage'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64-datacenter'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64-enterprise'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::r2:x64-standard'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:compute_cluster'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:datacenter'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:enterprise'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:itanium'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:standard'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:storage'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp1:x64'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:compute_cluster'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:datacenter'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:enterprise'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:itanium'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:standard'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:storage'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server::sp2:x64'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_2003_server:-:r2_sp2'] = '14 Jul 2015';

#Windows 2003 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_server_2003'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Microsoft%20Windows%20Server%202003&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_server_2003:::x64'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_server_2003::sp2'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_server_2003::sp2:itanium'] = '14 Jul 2015';
eol_cpes['cpe:/o:microsoft:windows_server_2003::sp2:x64'] = '14 Jul 2015';

#Windows 7 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%207&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_7'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%207&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_7:-:-:x32'] = '09 Apr 2013';
eol_cpes['cpe:/o:microsoft:windows_7:::x32'] = '09 Apr 2013';
eol_cpes['cpe:/o:microsoft:windows_7:-:-:x64'] = '09 Apr 2013';
eol_cpes['cpe:/o:microsoft:windows_7:::x64'] = '09 Apr 2013';
eol_cpes['cpe:/o:microsoft:windows_7:-:-:'] = '09 Apr 2013';
eol_cpes['cpe:/o:microsoft:windows_7:::'] = '09 Apr 2013';

#Windows 8 (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%208&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_8'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%208&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_8'] = '12 Jan 2016';
eol_cpes['cpe:/o:microsoft:windows_8:-:-:x86'] = '12 Jan 2016';
eol_cpes['cpe:/o:microsoft:windows_8:-:sp1:x86'] = '12 Jan 2016';
eol_cpes['cpe:/o:microsoft:windows_8:-:-:x64'] = '12 Jan 2016';
eol_cpes['cpe:/o:microsoft:windows_8:-:sp1:x64'] = '12 Jan 2016';

#Windows Vista (https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%20Vista&Filter=FilterNO)
eol_urls['cpe:/o:microsoft:windows_vista'] = 'https://support.microsoft.com/en-us/lifecycle/search?sort=PN&alpha=Windows%20Vista&Filter=FilterNO';
eol_cpes['cpe:/o:microsoft:windows_vista'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp1'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp2'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:-:x86'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:-:x64'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp1:x86'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp2:x86'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp1:x64'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:-:sp2:x64'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::gold'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:::x86'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:::x64'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:::x86-enterprise'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:::x86-ultimate'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:::x64-enterprise'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista:::x64-ultimate'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x86'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x86-enterprise'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x86-ultimate'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64-enterprise'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64-ultimate'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp1:x64-home_premium'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp2'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp2:x86'] = '11 Apr 2017';
eol_cpes['cpe:/o:microsoft:windows_vista::sp2:x64'] = '11 Apr 2017';

#Windows 10 (https://support.microsoft.com/en-US/help/13853/windows-lifecycle-fact-sheet)
eol_urls['cpe:/o:microsoft:windows_10'] = 'https://support.microsoft.com/en-US/help/13853/windows-lifecycle-fact-sheet';
eol_cpes['cpe:/o:microsoft:windows_10:1507'] = '09 May 2017';

function get_eol_url(cpe) {

  if(!cpe) return FALSE;

  if(eol_urls[cpe]) # for some windows cpes
    return eol_urls[cpe];

  _cpe = split(cpe,sep:":",keep:FALSE);

  if (_cpe && _cpe[0] && _cpe[1] && _cpe[2] && _cpe[3]) {
    cpe = _cpe[0] + ':' + _cpe[1] + ':' + _cpe[2] + ':' + _cpe[3];
  }

  if(":-:lts" >< cpe) # for ubuntu lts
    cpe += ':-:lts';

  if(!eol_urls[cpe]) return FALSE;

  return eol_urls[cpe];

}

function get_eol_date(cpe) {

  if(!cpe) return FALSE;
  if(!eol_cpes[cpe]) return FALSE;

  eol_date = eol_cpes[cpe];

  if("unknown" >< eol_date) return FALSE;

  return eol_date;

}

function build_eol_message(cpe) {

  if(!cpe) return "";

  eol_url = get_eol_url(cpe:cpe);
  eol_date = get_eol_date(cpe:cpe);

  message = 'The Operating System (' + cpe  + ') on the remote host has reached the end of life';

  if(eol_date)
    message +=  ' at ' + eol_date;

  message += '\nand should not be used anymore.';

  if(eol_url)
    message += '\nSee ' + eol_url + ' for more information.\n';

  return message;

}
