'''

This file is copied from https://github.com/williballenthin/ida-netnode
and is reproduced under the following license:

                              Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "{}"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright {yyyy} {name of copyright owner}

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

import zlib
import json
import logging

import idaapi

BLOB_SIZE = 1024
OUR_NETNODE = "$ com.williballenthin"
INT_KEYS_TAG = 'M'
STR_KEYS_TAG = 'N'
STR_TO_INT_MAP_TAG = 'O'
INT_TO_INT_MAP_TAG = 'P'
logger = logging.getLogger(__name__)


class NetnodeCorruptError(RuntimeError):
    pass


class Netnode(object):
    """
    A netnode is a way to persistently store data in an IDB database.
    The underlying interface is a bit weird, so you should read the IDA
      documentation on the subject. Some places to start:

      - https://www.hex-rays.com/products/ida/support/sdkdoc/netnode_8hpp.html
      - The IDA Pro Book, version 2

    Conceptually, this netnode class represents is a key-value store
      uniquely identified by a namespace.

    This class abstracts over some of the peculiarities of the low-level
      netnode API. Notably, it supports indexing data by strings or
      numbers, and allows values to be larger than 1024 bytes in length.

    This class supports keys that are numbers or strings.
    Values must be JSON-encodable. They can not be None.

    Implementation:
     (You don't have to worry about this section if you just want to
        use the library. Its here for potential contributors.)

      The major limitation of the underlying netnode API is the fixed
        maximum length of a value. Values must not be larger than 1024
        bytes. Otherwise, you must use the `blob` API. We do that for you.

      The first enhancement is transparently zlib-encoding all values.

      To support arbitrarily sized values with keys of either int or str types,
        we store the values in different places:

        - integer keys with small values: stored in default supval table
        - integer keys with large values: the data is stored in the blob
           table named 'M' using an internal key. The link from the given key
           to the internal key is stored in the supval table named 'P'.
        - string keys with small values: stored in default hashval table
        - string keys with large values: the data is stored in the blob
           table named 'N' using an integer key. The link from string key
           to int key is stored in the supval table named 'O'.
    """
    def __init__(self, netnode_name=OUR_NETNODE):
        self._netnode_name = netnode_name
        #self._n = idaapi.netnode(netnode_name, namelen=0, do_create=True)
        self._n = idaapi.netnode(netnode_name, 0, True)

    @staticmethod
    def _decompress(data):
        return zlib.decompress(data)

    @staticmethod
    def _compress(data):
        return zlib.compress(data)

    @staticmethod
    def _encode(data):
        return json.dumps(data)

    @staticmethod
    def _decode(data):
        return json.loads(data)

    def _intdel(self, key):
        assert isinstance(key, (int, long))

        did_del = False
        storekey = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey)
            self._n.delblob(storekey, INT_KEYS_TAG)
            self._n.supdel(key)
            did_del = True
        if self._n.supval(key) is not None:
            self._n.supdel(key)
            did_del = True

        if not did_del:
            raise KeyError("'{}' not found".format(key))

    def _get_next_slot(self, tag):
        '''
        get the first unused supval table key, or 0 if the
         table is empty.
        useful for filling the supval table sequentially.
        '''
        slot = self._n.suplast(tag)
        if slot is None or slot == idaapi.BADNODE:
            return 0
        else:
            return slot + 1

    def _intset(self, key, value):
        assert isinstance(key, (int, long))
        assert value is not None

        try:
            self._intdel(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            storekey = self._get_next_slot(INT_KEYS_TAG)
            self._n.setblob(value, storekey, INT_KEYS_TAG)
            self._n.supset(key, str(storekey), INT_TO_INT_MAP_TAG)
        else:
            self._n.supset(key, value)

    def _intget(self, key):
        assert isinstance(key, (int, long))

        storekey = self._n.supval(key, INT_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey)
            v = self._n.getblob(storekey, INT_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.supval(key)
        if v is not None:
            return v

        raise KeyError("'{}' not found".format(key))

    def _strdel(self, key):
        assert isinstance(key, (basestring))

        did_del = False
        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey)
            self._n.delblob(storekey, STR_KEYS_TAG)
            self._n.hashdel(key)
            did_del = True
        if self._n.hashval(key):
            self._n.hashdel(key)
            did_del = True

        if not did_del:
            raise KeyError("'{}' not found".format(key))

    def _strset(self, key, value):
        assert isinstance(key, (basestring))
        assert value is not None

        try:
            self._strdel(key)
        except KeyError:
            pass

        if len(value) > BLOB_SIZE:
            storekey = self._get_next_slot(STR_KEYS_TAG)
            self._n.setblob(value, storekey, STR_KEYS_TAG)
            self._n.hashset(key, str(storekey), STR_TO_INT_MAP_TAG)
        else:
            self._n.hashset(key, value)

    def _strget(self, key):
        assert isinstance(key, (basestring))

        storekey = self._n.hashval(key, STR_TO_INT_MAP_TAG)
        if storekey is not None:
            storekey = int(storekey)
            v = self._n.getblob(storekey, STR_KEYS_TAG)
            if v is None:
                raise NetnodeCorruptError()
            return v

        v = self._n.hashval(key)
        if v is not None:
            return v

        raise KeyError("'{}' not found".format(key))

    def __getitem__(self, key):
        if isinstance(key, basestring):
            v = self._strget(key)
        elif isinstance(key, (int, long)):
            v = self._intget(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

        return self._decode(self._decompress(v))

    def __setitem__(self, key, value):
        '''
        does not support setting a value to None.
        value must be json-serializable.
        key must be a string or integer.
        '''
        assert value is not None

        v = self._compress(self._encode(value))
        if isinstance(key, basestring):
            self._strset(key, v)
        elif isinstance(key, (int, long)):
            self._intset(key, v)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def __delitem__(self, key):
        if isinstance(key, basestring):
            self._strdel(key)
        elif isinstance(key, (int, long)):
            self._intdel(key)
        else:
            raise TypeError("cannot use {} as key".format(type(key)))

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def __contains__(self, key):
        try:
            if self[key] is not None:
                return True
            return False
        except KeyError:
            return False

    def iterkeys(self):
        # integer keys for all small values
        i = self._n.sup1st()
        while i != idaapi.BADNODE:
            yield i
            i = self._n.supnxt(i)

        # integer keys for all big values
        i = self._n.sup1st(INT_TO_INT_MAP_TAG)
        while i != idaapi.BADNODE:
            yield i
            i = self._n.supnxt(i, INT_TO_INT_MAP_TAG)

        # string keys for all small values
        i = self._n.hash1st()
        while i != idaapi.BADNODE and i is not None:
            yield i
            i = self._n.hashnxt(i)

        # string keys for all big values
        i = self._n.hash1st(STR_TO_INT_MAP_TAG)
        while i != idaapi.BADNODE and i is not None:
            yield i
            i = self._n.hashnxt(i, STR_TO_INT_MAP_TAG)

    def keys(self):
        return [k for k in self.iterkeys()]

    def itervalues(self):
        for k in self.iterkeys():
            yield self[k]

    def values(self):
        return [v for v in self.itervalues()]

    def iteritems(self):
        for k in self.iterkeys():
            yield k, self[k]

    def items(self):
        return [(k, v) for k, v in self.iteritems()]

    def kill(self):
        self._n.kill()
        self._n = idaapi.netnode(self._netnode_name, 0, True)
