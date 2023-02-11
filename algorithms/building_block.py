from collections.abc import Iterable

from algorithms.building_block_id_manager import BuildingBlockIDManager
from dataloader.datapacket import Datapacket


class BuildingBlock:
    """
    base class for features and other algorithms
    """

    def __init__(self):
        self.__config = BuildingBlock.__arguments()
        self.__instance_id = None        
        self.__last_result = None
        self.__last_datapacket_id = None

    def train_on(self, datapacket: Datapacket):
        """
        takes one datapacket to train this bb
        """        

    def val_on(self, datapacket: Datapacket):
        """
        takes one datapacket to validate this bb on
        """

    def fit(self):
        """
        finalizes training
        """

    def get_result(self, datapacket: Datapacket):
        """        
        This function calculates this building block on the given datapacket.
        It buffers its result until another datapacket is given.
        Returns its value (whatever it is) or None if it cant be calculated at the moment.
        """
        if self.__last_datapacket_id != id(datapacket):
            self.__last_result = self._calculate(datapacket)
            self.__last_datapacket_id = id(datapacket)
        return self.__last_result

    def _calculate(self, datapacket: Datapacket):
        """
        calculates building block on the given datapacket
        """
        raise NotImplementedError("each building block has to implement _calculate")

    def new_recording(self):
        """
        empties buffer and prepares for next recording
        """

    def depends_on(self) -> list:
        """
        gives information about the dependencies of this building block
        """
        raise NotImplementedError("each building block has to implement depends_on to indicate its dependencies")

    def __str__(self) -> str:
        """
        gives a more or less human readable str representation of this object
        returns: "Name_of_class(memory_address)"
        """        
        result = ""
        if len(self.__config) > 0:
            config = str(self.__config)            
            result = f"{self.__class__.__name__}({hex(id(self))}, {config})"
        else:
            result = f"{self.__class__.__name__}({hex(id(self))})"
        #print(result)
        return result

    def __repr__(self):
        """
        same for __repr__
        """
        return self.__str__()

    def get_id(self):
        """
        returns the id of this feature instance - used to differ between different building blocks
        """
        if self.__instance_id is None:
            self.__instance_id = BuildingBlockIDManager().get_id(self)
        return self.__instance_id

    def __arguments():
            """Returns tuple containing dictionary of calling function's
            named arguments and a list of calling function's unnamed
            positional arguments.
            from: http://kbyanc.blogspot.com/2007/07/python-aggregating-function-arguments.html
            """
            from inspect import getargvalues, stack
            try:
                _ , kwname, args = getargvalues(stack()[2][0])[-3:] # modified the first index to get the correct arguments
                args.update(args.pop(kwname, []))
                del args['self']
                del args['__class__']
                final_args = {}
                for k,v in args.items():
                    #print(f"at {k}")
                    if not isinstance(v, BuildingBlock) and (isinstance(v, str) or not isinstance(v, Iterable)):                        
                        final_args[k] = v                    
                    if isinstance(v, Iterable) and not isinstance(v, str):
                        final_iter = []
                        for item in v:
                            if not isinstance(item, BuildingBlock):
                                final_iter.append(item)
                        if len(final_iter) > 0:
                            final_args[k] = final_iter                            
                return final_args
            except KeyError:
                return {}