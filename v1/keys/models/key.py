from django.db import models
from thenewboston.models.network_transaction import NetworkTransaction

from v1.blocks.models.block import Block


class Key(models.Model):
    patient_id = models.UUIDField(editable=False, primary_key=True)
    encrypted_symmetric_key = models.UUIDField(editable=False)

    class Meta:
        default_related_name = 'bank_transactions'

    def __str__(self):
        return (
            f'patient_id: {self.id} | '
            f'encrypted_symmetric_key: {self.encrypted_symmetric_key or "-"}'
        )
