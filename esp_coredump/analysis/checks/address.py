#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Rule: say where the crash PC and the bad address point to.
"""

from .base import NEAR_ZERO_LIMIT, Rule, app_section_at, code_section, get_fact

# (fact id, subject, name used in the text)
ADDRESS_FACTS = (
    ('fact:pc', 'pc', 'The PC'),
    ('fact:bad-address', 'bad-address', 'The bad address'),
)

PRINTABLE = range(0x20, 0x7F)


class AddressClassRule(Rule):
    id = 'address-class.v1'
    needs = ('fact:pc', 'fact:bad-address', 'elf.sections', 'rom.sections', 'memory_areas')

    def run(self, report):
        span = self._section_span(report)
        results = []
        for fact_id, subject, name in ADDRESS_FACTS:
            fact = get_fact(report, fact_id)
            if fact is None:
                if subject == 'pc':
                    results.append(self.not_enough_data('The crash PC is not available.', subject=subject))
                # a missing bad address is normal, for example for abort()
                continue
            pc = get_fact(report, 'fact:pc')
            if subject == 'bad-address' and pc is not None and pc.value == fact.value:
                # a fetch fault at the PC, the result for the PC already says it
                continue
            results.append(self._classify(report, fact, subject, name, span))
        return results

    def _classify(self, report, fact, subject, name, span):
        addr = fact.value
        evidence = [fact.id]
        area = next((a for a in report.memory_areas if a.contains(addr)), None)
        if area is not None:
            evidence.append(area.id)

        if addr == 0:
            return self.found(f'{name} 0x{addr:08x} is a NULL pointer.', evidence, subject, 'near_zero')
        if addr < NEAR_ZERO_LIMIT:
            return self.found(
                f'{name} 0x{addr:08x} is near zero (NULL + 0x{addr:x}). This often means a NULL pointer used with a small offset.',
                evidence,
                subject,
                'null_plus_offset',
            )
        rom = code_section(report, addr)
        if rom is not None and rom[1]:
            evidence.append('fact:rom-elf')
            return self.confirmed(f'{name} 0x{addr:08x} is in ROM code ({rom[0]}).', evidence, subject, 'rom_code')
        section = app_section_at(report, addr)
        if section is not None and section.kind == 'code':
            return self.confirmed(f'{name} 0x{addr:08x} is in the app code ({section.name}).', evidence, subject, 'elf_code')
        if section is not None:
            return self.confirmed(f'{name} 0x{addr:08x} is in the app data ({section.name}).', evidence, subject, 'elf_data')
        if area is not None:
            return self.confirmed(f'{name} 0x{addr:08x} is in saved memory ({area.kind}), not in the app ELF.', evidence, subject, 'captured_memory')
        if all(b in PRINTABLE for b in addr.to_bytes(4, 'little')):
            return self.found(
                f'{name} 0x{addr:08x} is four printable ASCII bytes, so text or payload data was used as an address.',
                evidence,
                subject,
                'looks_like_ascii',
            )
        if span is not None and not span[0] <= addr < span[1]:
            return self.confirmed(
                f'{name} 0x{addr:08x} is outside the app address range 0x{span[0]:08x}..0x{span[1]:08x}. '
                'It can still be ROM, a peripheral register or memory the dump does not save.',
                evidence,
                subject,
                'outside_app_range',
            )
        rest = 'a peripheral, heap or a bad address' if report.rom is not None else 'ROM, a peripheral, heap or a bad address'
        return self.confirmed(
            f'{name} 0x{addr:08x} is not in the app ELF. It can be {rest}.',
            evidence,
            subject,
            'unknown',
        )

    @staticmethod
    def _section_span(report):
        """The lowest start and highest end of the loaded ELF sections."""
        starts = [s.start for s in report.elf.sections]
        ends = [s.start + s.size for s in report.elf.sections]
        return (min(starts), max(ends)) if starts else None
