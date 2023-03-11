from algorithms.building_block import BuildingBlock


class FeatureSet(BuildingBlock):
    """
    base class for feature-set
    """

    def __init__(self):
        super().__init__()

    def set_host_ip(self, host_ip):
        """
        set host ip
        """
        raise NotImplemented
